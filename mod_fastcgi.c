/* 
 * mod_fastcgi.c --
 *
 *      Apache server module for FastCGI.
 *
 *
 *  Copyright (c) 1995-1996 Open Market, Inc.
 *
 *  See the file "LICENSE.TERMS" for information on usage and redistribution
 *  of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 *
 *
 *  Patches for Apache-1.1 provided by
 *  Ralf S. Engelschall
 *  <rse@en.muc.de>
 *
 *  Patches for Linux provided by
 *  Scott Langley
 *  <langles@vote-smart.org>
 */

/*
 * Module design notes.
 *
 * 1. Restart cleanup.
 *
 *   mod_fastcgi spawns several processes: one process manager process
 *   and several application processes.  None of these processes
 *   handle SIGHUP, so they just go away when the Web server performs
 *   a restart (as Apache does every time it starts.)
 *
 *   In order to allow the process manager to properly cleanup the 
 *   running fastcgi processes (without being disturbed by Apache), 
 *   an intermediate process was introduced.  The diagram is as follows;
 *  
 *   ApacheWS --> MiddleProc --> ProcMgr --> FCGI processes
 *
 *   On a restart, ApacheWS sends a SIGKILL to MiddleProc and then
 *   collects it via waitpid().  The ProcMgr periodically checks for
 *   its parent (via getppid()) and if it does not have one, as in 
 *   case when MiddleProc has terminated, ProcMgr issues a SIGTERM 
 *   to all FCGI processes, waitpid()s on them and then exits, so it 
 *   can be collected by init(1).  Doing it any other way (short of
 *   changing Apache API), results either in inconsistent results or 
 *   in generation of zombie processes.
 *
 *   XXX: How does Apache 1.2 implement "gentle" restart
 *   that does not disrupt current connections?  How does
 *   gentle restart interact with restart cleanup?
 *
 * 2. Request timeouts.
 *
 *   The Apache TimeOut directive specifies a timeout not for the entire
 *   request, but a timeout that applies separately to each thing that
 *   might time out.  In the case of CGI:
 *
 *     reading the request from the client
 *     sending the request to a CGI application
 *     reading the response from a CGI application
 *     sending the response to the client.
 *
 *  FastCGI pipelines the I/O (can be sending the response to the
 *  client while still reading the request from the client) so this
 *  model breaks down.  mod_fastcgi applies the timeout to the entire
 *  request.
 *
 *  mod_fastcgi uses the Apache soft_timeout function for its
 *  timeouts.  In case of a timeout, soft_timeout breaks the
 *  client connection by calling shutdown from the signal handler.
 *  This means that subsequent attempts to do client I/O will fail.
 *  mod_fastcgi continues request processing until the FastCGI application
 *  finishes its work, then cleans up the request.  (Shutting down early
 *  would require the FastCGI application to handle SIGPIPE.)
 *
 *  XXX: If the application hangs after reading all input and producing
 *  no output, you need to time out the application.  That's not
 *  currently implemented for the lack of a clean way to get the timeout
 *  information.
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>

#ifdef __EMX__
/* If this value is changed. Make sure you also change it in conf.h */
#define MAXSOCKETS 4096
/* OS/2 does not support groups, but we still want to call funcs */
typedef gid_t long;
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <netdb.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/time.h>

/*
 * Apache header files
 */
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_main.h"
#include "http_log.h"
#include "util_script.h"
#include "http_conf_globals.h"
#include "util_md5.h"

#if APACHE_RELEASE < 1030000
#define ap_md5(a,b) md5(a,b)
#endif

#include "mod_fastcgi.h"
#include "fastcgi.h"
#include "fcgitcl.h"
#include "fcgios.h"
#include "fcgibuf.h"

void *Malloc(size_t size)
{
    void *result;

    ASSERT(size>=0);
    result = malloc(size);
    ASSERT(size == 0 || result != NULL);
    memset(result, 0, size);
    return result;
}

void Free(void *ptr)
{
    if(ptr != NULL) {
        free(ptr);
    }
}

/*
 * XXX: why is this defined as void * not OS_IpcAddr * ?
 */
typedef void *OS_IpcAddress;

typedef struct _OS_IpcAddr {
    int addrType;                  /* one of TYPE_* below */
    int port;                      /* port used for TCP connections */
    DString bindPath;              /* Path used for the socket bind point */
    struct sockaddr *serverAddr;   /* server address (for connect) */
    int addrLen;                   /* length of server address (for connect) */
} OS_IpcAddr;

/*
 * Values of addrType field.
 */
#define TYPE_UNKNOWN 0              /* Uninitialized address type */
#define TYPE_LOCAL   1              /* Local IPC: UNIX domain stream socket */
#define TYPE_TCP     2              /* TCP stream socket */

/*
 *----------------------------------------------------------------------
 *
 * OS_InitIpcAddr --
 *
 *      Allocate and initialize an OS-specific IPC address structure.
 *
 * Results:
 *      IPC Address is initialized.
 *
 * Side effects:  
 *      Memory allocated.
 *
 *----------------------------------------------------------------------
 */  

OS_IpcAddress OS_InitIpcAddr(void)
{
    OS_IpcAddr *ipcAddrPtr = (OS_IpcAddr *)Malloc(sizeof(OS_IpcAddr));
    ipcAddrPtr->addrType = TYPE_UNKNOWN;
    ipcAddrPtr->port = -1;    
    DStringInit(&ipcAddrPtr->bindPath);
    ipcAddrPtr->serverAddr = NULL;
    ipcAddrPtr->addrLen = 0;
    return (OS_IpcAddress)ipcAddrPtr;
}

/*
 *----------------------------------------------------------------------
 *
 * OS_BuildSockAddrUn --
 *
 *      Using the pathname bindPath, fill in the sockaddr_un structure
 *      *servAddrPtr and the length of this structure *servAddrLen.
 *
 *      The format of the sockaddr_un structure changed incompatibly in
 *      4.3BSD Reno.
 *
 * Results:
 *      0 for normal return, -1 for failure (bindPath too long).
 *
 *----------------------------------------------------------------------
 */

static int OS_BuildSockAddrUn(
        char *bindPath,
        struct sockaddr_un *servAddrPtr,
        int *servAddrLen)
{
    int bindPathLen = strlen(bindPath);

#ifdef HAVE_SOCKADDR_UN_SUN_LEN /* 4.3BSD Reno and later: BSDI */
    if(bindPathLen >= sizeof(servAddrPtr->sun_path)) {
        return -1;
    }
#else                           /* 4.3 BSD Tahoe: Solaris, HPUX, DEC, ... */
    if(bindPathLen > sizeof(servAddrPtr->sun_path)) {
        return -1;
    }
#endif
    memset((char *) servAddrPtr, 0, sizeof(*servAddrPtr));
    servAddrPtr->sun_family = AF_UNIX;
    memcpy(servAddrPtr->sun_path, bindPath, bindPathLen);

#ifdef HAVE_SOCKADDR_UN_SUN_LEN /* 4.3BSD Reno and later: BSDI */
    *servAddrLen = sizeof(servAddrPtr->sun_len)
            + sizeof(servAddrPtr->sun_family)
            + bindPathLen + 1;
    servAddrPtr->sun_len = *servAddrLen;
#else                           /* 4.3 BSD Tahoe: Solaris, HPUX, DEC, ... */
    *servAddrLen = sizeof(servAddrPtr->sun_family) + bindPathLen;
#endif
    return 0;
}

/*
 *----------------------------------------------------------------------
 *
 * OS_CreateLocalIpcFd --
 *
 *      This procedure is responsible for creating the listener socket
 *      on Unix for local process communication.  It will create a Unix
 *      domain socket, bind it, and return a file descriptor to it to the
 *      caller.
 *
 * Results:
 *      Valid file descriptor or -1 on error.
 *
 * Side effects:  
 *      *ipcAddress initialized.
 *
 *----------------------------------------------------------------------
 */
typedef char *MakeSocketNameProc(char *execPath, char *bindPath, 
        int extension, Tcl_DString *dsPtr, int dynamic);

int OS_CreateLocalIpcFd(
        OS_IpcAddress ipcAddress, 
        int listenQueueDepth,
        uid_t uid, 
        gid_t gid, 
        MakeSocketNameProc makeSocketName,
	char *execPath, 
        char *bindPath,
        int extension,
	int dynamic)
{
    OS_IpcAddr *ipcAddrPtr = (OS_IpcAddr *)ipcAddress;
    struct sockaddr_un *addrPtr = NULL;
    int listenSock = -1;
    ASSERT(ipcAddrPtr->addrType == TYPE_UNKNOWN);

    /*
     * Build the domain socket address.
     */
    addrPtr = (struct sockaddr_un *) Malloc(sizeof(struct sockaddr_un));
    ipcAddrPtr->serverAddr = (struct sockaddr *) addrPtr;
    if (OS_BuildSockAddrUn(
            makeSocketName(execPath, bindPath, 
                    extension, &ipcAddrPtr->bindPath, dynamic),
            addrPtr, &ipcAddrPtr->addrLen)) {
        goto GET_IPC_ERROR_EXIT;
    }
    ipcAddrPtr->addrType = TYPE_LOCAL;
    unlink(DStringValue(&ipcAddrPtr->bindPath));

    /*
     * Create the listening socket to be used by the fcgi server.
     */
    if((listenSock = OS_Socket(ipcAddrPtr->serverAddr->sa_family,
                               SOCK_STREAM, 0)) < 0) {
        goto GET_IPC_ERROR_EXIT;
    }

    /*
     * Bind the listening socket and set it to listen.
     */
    if(OS_Bind(listenSock, ipcAddrPtr->serverAddr, ipcAddrPtr->addrLen) < 0
       || OS_Listen(listenSock, listenQueueDepth) < 0) {
        goto GET_IPC_ERROR_EXIT;
    }
#ifndef __EMX__
     /* OS/2 doesn't support changing ownership. */
    chown(DStringValue(&ipcAddrPtr->bindPath), uid, gid);
#endif    

    chmod(DStringValue(&ipcAddrPtr->bindPath), S_IRUSR | S_IWUSR);
    return listenSock;

GET_IPC_ERROR_EXIT:
    if(listenSock != -1)
        OS_Close(listenSock);
    if(addrPtr != NULL) {
        free(addrPtr);
        ipcAddrPtr->serverAddr = NULL;
        ipcAddrPtr->addrType = TYPE_UNKNOWN;    
        ipcAddrPtr->addrLen = 0;
    }
    return -1;
}

/*
 *----------------------------------------------------------------------
 *
 * OS_FreeIpcAddr --
 *
 *      Free up and clean up an OS IPC address.
 *
 * Results:
 *      IPC Address is freed.
 *
 * Side effects:  
 *      More memory.
 *
 *----------------------------------------------------------------------
 */  
void OS_FreeIpcAddr(OS_IpcAddress ipcAddress)
{
    OS_IpcAddr *ipcAddrPtr = (OS_IpcAddr *)ipcAddress;
    
    DStringFree(&ipcAddrPtr->bindPath); 
    Free(ipcAddrPtr->serverAddr);
    ipcAddrPtr->addrLen = 0;
    Free(ipcAddrPtr);
}

/*
 *----------------------------------------------------------------------
 *
 * OS_CreateRemoteIpcFd --
 *
 *      This procedure is responsible for creating a listener socket 
 *      for remote process communication.  It will create a TCP socket,
 *      bind it, and return a file descriptor to the caller. 
 *
 * Results:
 *      Valid file descriptor or -1 on error.
 *
 *----------------------------------------------------------------------
 */

int OS_CreateRemoteIpcFd(
        OS_IpcAddress ipcAddress,
        int portIn,
        int listenQueueDepth)
{
    OS_IpcAddr *ipcAddrPtr = (OS_IpcAddr *) ipcAddress;
    struct sockaddr_in *addrPtr = (struct sockaddr_in *) 
                                  Malloc(sizeof(struct sockaddr_in));
    int resultSock = -1;
    int flag = 1;

    ASSERT(ipcAddrPtr->addrType == TYPE_UNKNOWN);
    ipcAddrPtr->addrType = TYPE_TCP;
    ipcAddrPtr->port = portIn;
    ipcAddrPtr->addrLen = sizeof(struct sockaddr_in);

    memset((char *) addrPtr, 0, sizeof(struct sockaddr_in));
    addrPtr->sin_family = AF_INET;
    addrPtr->sin_addr.s_addr = htonl(INADDR_ANY);
    addrPtr->sin_port = htons(portIn);
    ipcAddrPtr->serverAddr = (struct sockaddr *) addrPtr;

    if((resultSock = OS_Socket(ipcAddrPtr->serverAddr->sa_family, 
                                SOCK_STREAM, 0)) < 0) {
        goto GET_IPC_ERROR_EXIT;
    }

    if(setsockopt(resultSock, SOL_SOCKET, SO_REUSEADDR,
                  (char *) &flag, sizeof(flag)) < 0) {
        goto GET_IPC_ERROR_EXIT;
    }

    /*
     * Bind the listening socket and set it to listen
     */
    if(OS_Bind(resultSock, ipcAddrPtr->serverAddr, ipcAddrPtr->addrLen) < 0
        || OS_Listen(resultSock, listenQueueDepth) < 0) {
         goto GET_IPC_ERROR_EXIT;
      }

    return resultSock;
  
GET_IPC_ERROR_EXIT:
    if(resultSock != -1) {
        OS_Close(resultSock);
    }
    if(addrPtr != NULL) {
        Free(addrPtr);
        ipcAddrPtr->serverAddr = NULL;
        ipcAddrPtr->port = -1;
        ipcAddrPtr->addrType = TYPE_UNKNOWN;
        ipcAddrPtr->addrLen = 0;
    }
    return -1;
}

/*
 *----------------------------------------------------------------------
 *
 * ResolveHostname --
 *
 *      Given a hostname string (aegaen.openmarket.com) or an ASCII
 *      "dotted decimal" IP address (199.170.183.5), convert to 
 *      IP address.
 *
 *      NOTE: This routine will block as the hostname is resolved, and
 *            should only be used in startup or debugging code.
 *
 * Results:
 *      Returns -1 if error, and the number of resolved addresses (one
 *      or more), if success.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

int ResolveHostname(char *hostname, struct in_addr *addr)
{
    struct hostent *hp;
    int count;

    addr->s_addr = inet_addr(hostname);
    if(addr->s_addr == INADDR_NONE) {
        if((hp = gethostbyname(hostname)) == NULL) {
            return -1;
        }

        memcpy((char *) addr, hp->h_addr, hp->h_length);
        count = 0;
        while(hp->h_addr_list[count] != 0) {
            count++;
        }

        return count;
    }
    return 1;
}

/*
 *----------------------------------------------------------------------
 *
 * OS_CreateLocalIpcAddr --
 *
 *      This procedure is responsible for creating a Unix domain address
 *      to be used to connect to a fcgi server not managed by the Web
 *      server.
 *
 * Results:
 *      Unix Domain socket is created.  This call returns 0 on success
 *      or -1 on error.
 *
 * Side effects:
 *      OS_IpcAddress structure is allocated and returned to the caller.
 *      'errno' will set on errors (-1 is returned).
 *
 *----------------------------------------------------------------------
 */

int OS_CreateLocalIpcAddr(
        OS_IpcAddress ipcAddress,
        MakeSocketNameProc makeSocketName,
	char *execPath,
        char *bindPath,
        int extension,
	int dynamic)
{
    OS_IpcAddr *ipcAddrPtr = (OS_IpcAddr *) ipcAddress;
    struct sockaddr_un* addrPtr = NULL;
    ASSERT(ipcAddrPtr->addrType == TYPE_UNKNOWN);

    /*
     * Build the domain socket address.
     */
    addrPtr = (struct sockaddr_un *) Malloc(sizeof(struct sockaddr_un));
    ipcAddrPtr->serverAddr = (struct sockaddr *) addrPtr;
    if(OS_BuildSockAddrUn(makeSocketName(execPath, bindPath, 
			          extension, &ipcAddrPtr->bindPath,
                                  dynamic),
            addrPtr, &ipcAddrPtr->addrLen)) {
        goto GET_IPC_ADDR_ERROR;
    }
    ipcAddrPtr->addrType = TYPE_LOCAL;
    return 0;
    
GET_IPC_ADDR_ERROR:
    if(addrPtr != NULL) {
        free(addrPtr);
        ipcAddrPtr->serverAddr = NULL;
    }
    return -1;
}

/*
 *----------------------------------------------------------------------
 *
 * OS_CreateInetIpc --
 *
 *      This procedure is responsible for creating an OS_IpcAddr version
 *      of hostname:port to be used for communications via TCP.
 *
 * Results:
 *      AF_INET socket created.
 *
 * Side effects:
 *      OS_IpcAddress structure is allocated and returned to the caller.
 *
 *----------------------------------------------------------------------
 */
void OS_CreateInetIpc(
        OS_IpcAddress ipcAddress,
        struct in_addr *hostIn,
        int portIn)
{
     OS_IpcAddr *ipcAddrPtr = (OS_IpcAddr *) ipcAddress;
    struct sockaddr_in *addrPtr;
  
    ASSERT(ipcAddrPtr->addrType == TYPE_UNKNOWN);
    ipcAddrPtr->addrType = TYPE_TCP;
    ipcAddrPtr->port = portIn;

    addrPtr = (struct sockaddr_in *) Malloc(sizeof(struct sockaddr_in));
    memset(addrPtr, 0, sizeof(struct sockaddr_in));
    ipcAddrPtr->addrLen = sizeof(struct sockaddr_in);
    addrPtr->sin_family = AF_INET;
    addrPtr->sin_port = htons(portIn);
    memcpy(&addrPtr->sin_addr.s_addr, hostIn, sizeof(struct in_addr));
    ipcAddrPtr->serverAddr = (struct sockaddr *) addrPtr;
}


/* 
 * The number of open files per process
 */
#ifdef OPEN_MAX
#define MAX_OPEN_FDS OPEN_MAX
#else
#define MAX_OPEN_FDS (128)
#endif
/*
 *----------------------------------------------------------------------
 *
 * OS_ExecFcgiProgram --
 *
 *      Fork and exec the specified fcgi process.
 *
 * Results:
 *      0 for successful fork, -1 for failed fork.
 *      
 *      In case the child fails before or in the exec, the child
 *      obtains the error log by calling getErrLog, logs
 *      the error, and exits with exit status = errno of
 *      the failed system call.
 *
 * Side effects:  
 *      Child process created.
 *
 *----------------------------------------------------------------------
 */
typedef FILE *GetErrLog(void);

static int OS_ExecFcgiProgram(
        pid_t *childPid,
        int listenFd,
        int priority,
        char *programName,
        char **envPtr,
        GetErrLog *getErrLog)
{
    int i;
    DString dirName;
    char *dnEnd, *failedSysCall;
    FILE *errorLogFile;
    char *dispatchProgram = programName;
    int save_errno;

#ifdef RBOX_PATH
    dispatchProgram = RBOX_PATH;
#endif

    /*
     * Fork the fcgi process.
     */
    *childPid = fork();
    if(*childPid < 0) {
        return -1;
    } else if(*childPid != 0) {
        return 0;
    }

    /*
     * We're the child; no return.
     */
    if(!geteuid() && setuid(user_id) == -1) {
        failedSysCall = "setuid";
        goto ErrorExit;
    }
    if(listenFd != FCGI_LISTENSOCK_FILENO) {
        OS_Dup2(listenFd, FCGI_LISTENSOCK_FILENO);
        OS_Close(listenFd);
    }

    DStringInit(&dirName);
    dnEnd = strrchr(programName, '/');
    if(dnEnd == NULL) {
        DStringAppend(&dirName, "./", 1);
    } else {
        DStringAppend(&dirName, programName, dnEnd - programName);
    }
    if(chdir(DStringValue(&dirName)) < 0) {
        failedSysCall = "chdir";
        goto ErrorExit;
    }
    DStringFree(&dirName);

#ifndef __EMX__    
     /* OS/2 dosen't support nice() */
    if(priority != 0) {
        if(nice(priority) == -1) {
            failedSysCall = "nice";
            goto ErrorExit;
        }
    }
#endif

    /*
     * Close any file descriptors we may have gotten from the parent
     * process.  The only FD left open is the FCGI listener socket.
     */
    for(i=0; i < MAX_OPEN_FDS; i++) {
        if(i != FCGI_LISTENSOCK_FILENO) {
            OS_Close(i);
        }
    }
    do {
        if(envPtr != NULL) {
            execle(dispatchProgram, programName, NULL, envPtr);
            failedSysCall = "execle";
        } else {
            execl(dispatchProgram, programName, NULL);
            failedSysCall = "execl";
        }
    } while(errno == EINTR);

ErrorExit:
    save_errno = errno;
    /*
     * We had to close all files but the FCGI listener socket in order to
     * exec the application.  So if we want to report exec errors (we do!)
     * we must wait until now to open the log file.
     */
    errorLogFile = getErrLog();
    fprintf(errorLogFile,
            "[%s] mod_fastcgi: %s pid %ld syscall %s failed"
            " before entering app, errno = %s.\n",
            get_time(), programName, (long) getpid(), failedSysCall,
            strerror(save_errno));
    fflush(errorLogFile);
    exit(save_errno);
}

/*
 *----------------------------------------------------------------------
 * OS_Environ*
 *
 *      Allocate, fill in, and free a conventional environ structure
 *
 *----------------------------------------------------------------------
 */

static char **OS_EnvironInit(int envCount)
{
    return Malloc(sizeof(char *) * envCount);
}

static void OS_EnvString(char **envPtr, char *name, char *value)
{
    char *buf;
    ASSERT(name != NULL && value != NULL);
    buf = Malloc(strlen(name) + strlen(value) + 2);
    sprintf(buf, "%s=%s", name, value);
    ASSERT(*envPtr == NULL);
    *envPtr = buf;
}

static void OS_EnvironFree(char **envHead)
{
    char **envPtr = envHead;
    while(*envPtr != NULL) {
        Free(*envPtr);
        envPtr++;
  }
  Free(envHead);
}

/*
 *----------------------------------------------------------------------
 *
 * WS_Access --
 *
 *	Determine if a user with the specified user and group id
 *	will be able to access the specified file.  This routine depends
 *	on being called with enough permission to stat the file
 *	(e.g. root).
 *
 *	'mode' is the bitwise or of R_OK, W_OK, or X_OK.
 *
 *	This call is similar to the POSIX access() call, with extra
 *	options for specifying the user and group ID to use for 
 *	checking.
 *
 * Results:
 *      -1 if no access or error accessing, 0 otherwise.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */
#define WS_SET_errno(x) errno = x

int WS_Access(const char *path, struct stat *statBuf, 
        int mode, uid_t uid, gid_t gid)
{
    char **names;
    struct group *grp;
    struct passwd *usr;

    if(statBuf==NULL) {
        statBuf = (struct stat *)Malloc(sizeof(struct stat));
        if(stat(path, statBuf) < 0) {
	    return -1;
        }
    } 
    /*
     * If the user owns this file, check the owner bits.
     */
    if(uid == statBuf->st_uid) {
	WS_SET_errno(EACCES);
	if((mode & R_OK) && !(statBuf->st_mode & S_IRUSR)) {
	    goto no_access;
	}
	if((mode & W_OK) && !(statBuf->st_mode & S_IWUSR)) {
	    goto no_access;
	}
	if((mode & X_OK) && !(statBuf->st_mode & S_IXUSR)) {
	    goto no_access;
	}
	return 0;	
    }

#ifdef __EMX__
    /* OS/2 does not support groups */
    return 0;
#endif

    /*
     * If the user's group owns this file, check the group bits.
     */
    if(gid == statBuf->st_gid) {
	WS_SET_errno(EACCES);
	if((mode & R_OK) && !(statBuf->st_mode & S_IRGRP))
	    goto no_access;

	if((mode & W_OK) && !(statBuf->st_mode & S_IWGRP))
	    goto no_access;

	if((mode & X_OK) && !(statBuf->st_mode & S_IXGRP))
	    goto no_access;

	return 0;	
    }

    /*
     * Get the group information for the file group owner.  If the
     * user is a member of that group, apply the group permissions.
     */
    grp = getgrgid(statBuf->st_gid);
    if(grp == NULL) {
	return -1;
    }

    usr = getpwuid(uid);
    if(usr == NULL) {
	return -1;
    }

    for(names = grp->gr_mem; *names != NULL; names++) {
	if(!strcmp(*names, usr->pw_name)) {
	    WS_SET_errno(EACCES);
	    if((mode & R_OK) && !(statBuf->st_mode & S_IRGRP)) {
		goto no_access;
	    }
	    if((mode & W_OK) && !(statBuf->st_mode & S_IWGRP)) {
		goto no_access;
	    }
	    if((mode & X_OK) && !(statBuf->st_mode & S_IXGRP)) {
		goto no_access;
	    }
	    return 0;
        }
    }

    /*
     * If no matching user or group information, use 'other'
     * access information.  
     */
    if((mode & R_OK) && !(statBuf->st_mode & S_IROTH))
	goto no_access;

    if((mode & W_OK) && !(statBuf->st_mode & S_IWOTH))
	goto no_access;

    if((mode & X_OK) && !(statBuf->st_mode & S_IXOTH))
	goto no_access;

    return 0;

no_access:
    WS_SET_errno(EACCES);
    return -1;
}

/*
 * Done with the generic stuff.  Here starts the FastCGI stuff.
 */
typedef request_rec WS_Request;

#define FCGI_MAGIC_TYPE "application/x-httpd-fcgi"
#define FCGI_DEFAULT_LISTEN_Q 5            /* listen queue size */
#define FCGI_DEFAULT_RESTART_DELAY 5       /* delay between restarts */
#define FCGI_DEFAULT_PRIORITY 0            /* process priority - not used */
#define FCGI_ERRMSG_LEN 200                /* size of error buffer */
#define FCGI_MIN_EXEC_RETRY_DELAY 10       /* minimum number of seconds to 
					      wait before restarting */


/* Dynamic FastCGI applications */
#define FCGI_DEFAULT_MAX_PROCS  50         /* maximum number of processes that
					    * are allowed to run on system */
#define FCGI_DEFAULT_MIN_PROCS  5          /* minimum number of processes that
					    * can be run without being killed
					    * off by the process manager */
#define FCGI_DEFAULT_MAX_CLASS_PROCS 10    /* maximum number of processes that
					    * are allowed to run for a single
					    * application class */
#define FCGI_DEFAULT_KILL_INTERVAL 300     /* number of seconds in which we
					    * should execute the kill policy
					    * by killing off extra instances */
#define FCGI_DEFAULT_UPDATE_INTERVAL 300   /* number of seconds in which we
					    * should recalculate the value of
					    * totalConnTime variable */
#define FCGI_DEFAULT_GAIN 0.5              /* value used as an exponent in the
					    * calculation of the exponentially
					    * decayed connection times;
					    * old values are scaled by
					    * (1-gain), so making it
					    * smaller weights them more heavily
					    * compared to the current value,
					    * which is scaled by gain */
#define FCGI_DEFAULT_THRESHHOLD_1 10       /* if load falls below this value
					    * and we have only one instance
					    * running, it is killed off */
#define FCGI_DEFAULT_THRESHHOLD_N 50       /* if load falls below this value
					    * and we have more than one 
					    * instances, one is killed off */
#define FCGI_DEFAULT_START_PROCESS_DELAY 3 /* specifies the maximum number of 
					    * seconds a server should wait in
					    * attempt to connect to fcgi app
					    * before sending CONN_TIMEOUT */
#define FCGI_DEFAULT_APP_CONN_TIMEOUT 15   /* specified time interval, in 
					    * which attempt is made to connect
					    * to fcgi app.  If this interval 
					    * is exceeded, server returns a
					    * SERVER_ERROR message to client */
#define FCGI_DEFAULT_PROCESS_SLACK 5       /* if this number combined with the 
					    * number of the currently running 
					    * processes exceeds maxProcs, then
					    * the KillDynamicProcs() is invoked */
#define FCGI_DEFAULT_RESTART_DYNAMIC 0	   /* Do not restart dynamic processes */
#define FCGI_DEFAULT_AUTOUPDATE 0	   /* do not automatically restart
					    * fcgi apps when the binary on the
					    * disk is changed. */

/* 
 * FcgiProcessInfo holds info for each process specified in
 * an AppClass directive.  It is embedded in FastCgiServerInfo
 * below.
 */
typedef struct _FcgiProcessInfo {
    pid_t pid;                       /* pid of associated process */
    int listenFd;                    /* Listener socket */
    int fcgiFd;                      /* fcgi IPC file descriptor for
                                      * persistent connections.
                                      * Not used by Apache. */
    int state;                       /* state of the current process */
    OS_IpcAddress ipcAddr;           /* IPC Address of FCGI app server */
    struct _FastCgiServerInfo *serverInfoPtr;   /* Pointer to class parent */
} FcgiProcessInfo;

/*
 * Possible values for the state field above.
 */
#define STATE_STARTED        0     /* currently running */
#define STATE_NEEDS_STARTING 1     /* needs to be started by procMgr */
#define STATE_VICTIM         2     /* marked as a victim, was sent 
				    * the SIGTERM signal by procMgr */
#define STATE_KILLED         3     /* process is wait()ed on by the
				    * procMgr, so you can reuse this cell */
#define STATE_READY          4     /* not started, empty cell, initial state */

/*
 * FastCgiServerInfo holds info for each AppClass specified in this
 * Web server's configuration.
 */
typedef struct _FastCgiServerInfo {
    DString execPath;               /* pathname of executable */
    char      **envp;               /* if NOT NULL, this is the env to send
                                     * to the fcgi app when starting a server
                                     * managed app.
                                     */
    int listenQueueDepth;           /* size of listen queue for IPC */
    int numProcesses;               /* max allowed processes of this class,
				     * or for dynamic apps, the number of
				     * processes actually running */
    time_t restartTime;             /* most recent time when the process
                                     * manager started a process in this
                                     * class. */
    int restartDelay;               /* number of seconds to wait between
                                     * restarts after failure.  Can be zero.
                                     */
    int restartOnExit;              /* = TRUE = restart. else terminate/free.
                                     * Always TRUE for Apache. */
    int numRestarts;                /* Total number of restarts */
    int numFailures;                /* num restarts due to exit failure */
    OS_IpcAddress ipcAddr;          /* IPC Address of FCGI app server class.
                                     * Used to connect to an app server. */
    int directive;                  /* AppClass or ExternalAppClass */
    DString bindName;               /* Name used to create a socket */
    DString host;                   /* Hostname for externally managed 
                                     * FastCGI application processes */
    int port;                       /* Port number either for externally 
                                     * managed FastCGI applications or for
                                     * server managed FastCGI applications,
                                     * where server became application mngr. */
    int listenFd;                   /* Listener socket of FCGI app server
                                     * class.  Passed to app server process
                                     * at process creation. */
    int processPriority;            /* If locally server managed process,
                                     * this is the priority to run the
                                     * processes in this class at. */
    struct _FcgiProcessInfo *procInfo; /* Pointer to array of
                                     * processes belonging to this class. */
    int reqRefCount;                /* Number of requests active for this
                                     * server class.  Not used by Apache,
                                     * always zero. */
    int freeOnZero;                 /* Deferred free; free this structure
                                     * when refCount = 0.  Not used
                                     * by Apache. */
    int affinity;                   /* Session affinity.  Not used by 
                                     * Apache server. */
    int restartTimerQueued;         /* = TRUE = restart timer queued.
                                     * Not used by Apache. */
    int keepConnection;             /* = 1 = maintain connection to app. */
    int fcgiFd;                     /* fcgi IPC file descriptor for
                                     * persistent connections.  Not used
                                     * by Apache. */
    /* Dynamic FastCGI apps configuration parameters */
    unsigned long totalConnTime;    /* microseconds spent by the web server
				     * waiting while fastcgi app performs
				     * request processing since the last
				     * updateInterval */
    unsigned long smoothConnTime;   /* exponentially decayed values of the
				     * connection times. */
    unsigned long totalQueueTime;   /* microseconds spent by the web server
				     * waiting to connect to the fastcgi app
				     * since the last updateInterval.
				     * Not used by Apache. */
    unsigned long avgQueueTime;     /* exponentially decayed average of the
				     * time spent in queue.  Not used by
				     * Apache. */
    struct _FastCgiServerInfo *next;
} FastCgiServerInfo;

/* 
 * Value of directive field.
 */
#define APP_CLASS_UNKNOWN 0
#define APP_CLASS_STANDARD 1
#define APP_CLASS_EXTERNAL 2
#define APP_CLASS_DYNAMIC 3

/*
 * FastCgiInfo holds the state of a particular FastCGI request.
 */
typedef struct {
    int fd;                         /* connection to FastCGI server */
    int gotHeader;                  /* TRUE if reading content bytes */
    unsigned char packetType;       /* type of packet */
    int dataLen;                    /* length of data bytes */
    int paddingLen;                 /* record padding after content */
    FastCgiServerInfo *serverPtr;   /* FastCGI server info */
    Buffer *inbufPtr;               /* input buffer from server */
    Buffer *outbufPtr;              /* output buffer to server */
    Buffer *reqInbufPtr;            /* client input buffer */
    Buffer *reqOutbufPtr;           /* client output buffer */
    char *errorMsg;                 /* error message from failed request */
    int expectingClientContent;     /* >0 => more content, <=0 => no more */
    DString *header;
    DString *errorOut;
    int parseHeader;                /* TRUE iff parsing response headers */
    WS_Request *reqPtr;
    int readingEndRequestBody;
    FCGI_EndRequestBody endRequestBody;
    Buffer *erBufPtr;
    int exitStatus;
    int exitStatusSet;
    int requestId;
    int eofSent;
} FastCgiInfo;

/*
 * Values of parseHeader field
 */
#define SCAN_CGI_READING_HEADERS 1
#define SCAN_CGI_FINISHED        0
#define SCAN_CGI_BAD_HEADER     -1
#define SCAN_CGI_INT_REDIRECT   -2
#define SCAN_CGI_SRV_REDIRECT   -3

/*
 * Global variables
 *
 * A global that is really "own" to a single procedure
 * is declared with the procedure.
 */
static int readingConfig = FALSE;                /* AppClass but not init */
static FastCgiServerInfo *fastCgiServers = NULL; /* AppClasses */
static char *ipcDir = "/tmp";                    /* default FastCgiIpcDir */
static char *ipcDynamicDir = "/tmp/dynamic";     /* directory for the dynamic
						  * fastcgi apps' sockets */
static int globalNumInstances = 0;               /* number of running apps */
static time_t epoch = 0;                         /* last time kill_procs was
						  * invoked by process mgr */
static time_t lastAnalyze = 0;                   /* last time calculation was
						  * made for the dynamic procs*/
static char *mbox = "/tmp/mbox";                 /* file through which the fcgi
						  * procs communicate with WS */

static int maxProcs = FCGI_DEFAULT_MAX_PROCS;
static int minProcs = FCGI_DEFAULT_MIN_PROCS;
static int maxClassProcs = FCGI_DEFAULT_MAX_CLASS_PROCS;
static int killInterval = FCGI_DEFAULT_KILL_INTERVAL;
static int updateInterval = FCGI_DEFAULT_UPDATE_INTERVAL;
static float gain = FCGI_DEFAULT_GAIN;
static int threshhold1 = FCGI_DEFAULT_THRESHHOLD_1;
static int threshholdN = FCGI_DEFAULT_THRESHHOLD_N;
static int startProcessDelay = FCGI_DEFAULT_START_PROCESS_DELAY;
static int appConnTimeout = FCGI_DEFAULT_APP_CONN_TIMEOUT;
static int processSlack = FCGI_DEFAULT_PROCESS_SLACK;
static int restartDynamic = FCGI_DEFAULT_RESTART_DYNAMIC;
static int autoUpdate = FCGI_DEFAULT_AUTOUPDATE;

/*
 *----------------------------------------------------------------------
 *
 * Code related to the FastCgiIpcDir and AppClass commands.
 *
 *----------------------------------------------------------------------
 */

/* 
 *----------------------------------------------------------------------
 *
 * CreateDynamicDirAndMbox --
 * 
 *     Create a "dynamic" subdirectory in the directory specified by
 *     the FastCgiIpcDir.  The directory is created with the drwxr--r--
 *     permissions.  In the case the directory already exists, a check
 *     is made to assure the directory can be accessed by the current
 *     user/group.  Mbox file is created in the dynamic subdirectory to
 *     be used in the message passing between server and fastcgi app.
 *
 * Inputs:
 *     uid and gid of the current user.
 * 
 * Returns: 
 *     NULL or an error message
 */

static char *CreateDynamicDirAndMbox(uid_t uid, gid_t gid)
{
    DIR *dp = NULL;
    struct dirent *dirp = NULL;
    struct stat statbuf;
    char *dpentry = NULL;
    int len = strlen(ipcDir);
    int fd;

    ipcDynamicDir = Malloc(len+9);
    strcpy(ipcDynamicDir, ipcDir);
    strcat(ipcDynamicDir, "/dynamic");
    mbox = Malloc(len+9+5);
    strcpy(mbox, ipcDynamicDir);
    strcat(mbox, "/mbox");

    if(mkdir(ipcDynamicDir, S_IRWXU | S_IRGRP | S_IROTH)<0) {
        if(errno==EEXIST) {
	    /* always chown it just to make sure */
	    chown(ipcDynamicDir, uid, gid);
	    /* directory exists, check permissions and stat */
	    if(WS_Access(ipcDynamicDir, NULL, R_OK | W_OK | X_OK, uid, gid)) {
	        return
	            "Need read/write/exec permission for the \"dynamic\" dir";
	    }
	    /* stat is somewhat expensive */
	    if(lstat(ipcDynamicDir, &statbuf)<0) {
	        return 
                    "Unable to stat \"dynamic\" subdirectory";
	    }
	    if(!S_ISDIR(statbuf.st_mode)) {
	        return 
		    "\"dynamic\" is not a subdirectory";
	    }
	    goto DoMbox;
	} else {
	    return "Unable to create \"dynamic\" subdirectory";
	}
    }
    chown(ipcDynamicDir, uid, gid);
DoMbox:
    /* delete everything in the directory */
    dpentry = Malloc(strlen(ipcDynamicDir)+255);
    strcpy(dpentry, ipcDynamicDir);
    strcat(dpentry, "/");
    if((dp=opendir(ipcDynamicDir)) == NULL) {
        return 
	    "Unable to open dynamic directory for cleaning";
    }
    while((dirp=readdir(dp))!=NULL) {
        if((strcmp(dirp->d_name, ".") == 0) ||
	        (strcmp(dirp->d_name, "..") == 0)) {
	    continue;
	}
	memset(dpentry+strlen(ipcDynamicDir)+1, 0, 254);
	strcpy(dpentry+strlen(ipcDynamicDir)+1, dirp->d_name);
	unlink(dpentry);
    }
    closedir(dp);

    /* create mbox */
    if((fd=creat(mbox, S_IRUSR | S_IWUSR))<0) {
        return
            "Unable to create mbox file in dynamic subdirectory";
    }
    fchown(fd, uid, gid);
    close(fd);
    return NULL;
}

/*
 *----------------------------------------------------------------------
 *
 * FastCgiIpcDirCmd --
 *
 *     Sets up the directory into which Unix domain sockets 
 *     that are used for local communication will be deposited.
 *     Also create a subdirectory "dynamic" if one does not exist
 *     for the socket and lock files of dynamic FastCGI processes.
  *   
 * Results:
 *     NULL or an error message
 *
 *----------------------------------------------------------------------
 */

const char *FastCgiIpcDirCmd(cmd_parms *cmd, void *dummy, char *arg)
{
    uid_t uid;
    gid_t gid;
    int len;

    ASSERT(arg != NULL);
    len = strlen(arg);
    ASSERT(len > 0);
    if(*arg != '/') {
        return "FastCgiIpcDir: Directory path must be absolute\n";
    }

    uid = (user_id == (uid_t) -1)  ? geteuid() : user_id;
#ifndef __EMX__
    gid = (group_id == (gid_t) -1) ? getegid() : group_id;
#else
    gid = (gid_t)-1;
#endif
    if(WS_Access(arg, NULL, R_OK | W_OK | X_OK, uid, gid)) {
        return 
          "FastCgiIpcDir: Need read/write/exec permission on directory\n";
    }

    ipcDir = Malloc(len + 1);
    strcpy(ipcDir, arg);
    while(len > 1 && ipcDir[len-1] == '/') {
        ipcDir[len-1] = '\0';
        len--;
    }
    return CreateDynamicDirAndMbox(uid,gid);
}

/*
 *----------------------------------------------------------------------
 *
 * GetHashedPath --
 *
 *      Compute an MD5 hash of the "canonical" name of 
 *      the executable.  The canonical pathname is the one with
 *      "//", ".", "..", and symlinks removed.  
 *
 * Results:
 *      Printable string is computed.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */
#ifdef BUFSIZ
#define TMP_BUFSIZ (min(BUFSIZ, 512))
#else
#define TMP_BUFSIZ (512)
#endif

static pool *fcgiPool = NULL;
static char *GetHashedPath(char *bindName)
{
    char buffer[TMP_BUFSIZ];

    /* Canonicalize the string */
    getparents(bindName);
    memset(buffer, 0, TMP_BUFSIZ);
    if(readlink(bindName, buffer, TMP_BUFSIZ)<0) {
        if (errno!=EINVAL) {
	    return NULL;
	} else {
	    strncpy(buffer, bindName, TMP_BUFSIZ);
	}
    }

    /* Allocate private module memory pool */
    if(fcgiPool == NULL) {
        fcgiPool = make_sub_pool(NULL);
    }
    ASSERT(fcgiPool!=NULL);

    /* Hash the name - need to free memory on the SIGTERM */
    return ((char *)ap_md5(fcgiPool,(unsigned char *)buffer));
}
#undef TMP_BUFSIZ

/*
 *----------------------------------------------------------------------
 *
 * MakeSocketName --
 *
 *      Create a name for the Unix domain socket to be used
 *      for communication with local FastCGI applications.
 *      Last parameter specifies whether the socket filename
 *      should be created in the regular scoket directory, 
 *      specified by the ipcDir or its dynamic subdirectory,
 *      specified via ipcDynamicDir.
 *
 * Results:
 *      The value of the socket path name.
 *
 * Side effects:
 *      Appends to the DString.  
 *
 *----------------------------------------------------------------------
 */

char *MakeSocketName(char *execPath, char *bindPath, 
        int extension, Tcl_DString *dsPtr, int dynamic)
{
    char pathExt[32];
    
    ASSERT(DStringLength(dsPtr) == 0);
    if(dynamic==1) {
        DStringAppend(dsPtr, ipcDynamicDir, -1);
	DStringAppend(dsPtr, "/", -1);
    } else {
        DStringAppend(dsPtr, ipcDir, -1);
        DStringAppend(dsPtr, "/", -1);
    }

    /*
     * If bindPath is NULL, then it means that the name of
     * of the socket should be a canonical form of the execPath
     */
    if(bindPath==NULL) {
        DStringAppend(dsPtr, GetHashedPath(execPath), -1);
    } else {
        DStringAppend(dsPtr, bindPath, -1);
    }
    if(extension != -1) {
        sprintf(pathExt, ".%d", extension);
	DStringAppend(dsPtr, pathExt, -1);
    }
    return DStringValue(dsPtr);
}

/*
 * MakeLockFileName
 *
 * Returns the lock file name for dynamic application execName.
 * Allocates memory for it.
 */

char *
MakeLockFileName(char *execName)
{
  char *hashedPath, *lockName;

  hashedPath = GetHashedPath(execName);
  lockName = Malloc(strlen(ipcDynamicDir)+strlen(hashedPath)+7);
  strcpy(lockName, ipcDynamicDir);
  strcat(lockName, "/");
  strcat(lockName, hashedPath);
  strcat(lockName, ".lock");
  return lockName;
}

/*
 *----------------------------------------------------------------------
 *
 * LookupFcgiServerInfo --
 *
 *      Looks up the FastCgiServerInfo structure with info->execPath
 *      equal to ePath.
 *
 * Results:
 *      Pointer to the structure, or NULL if no such structure exists.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

FastCgiServerInfo *LookupFcgiServerInfo(char *ePath)
{
    FastCgiServerInfo *info;

    for(info = fastCgiServers; info != NULL; info = info->next) {
        const char *execPath = DStringValue(&info->execPath);
        if(execPath != NULL && strcmp(execPath, ePath) == 0) {
            return info;
        }
    }
    return NULL;
}

/*
 *----------------------------------------------------------------------
 *
 * CreateFcgiServerInfo --
 *
 *      This routine allocates and initializes a fast cgi server info
 *      structure.  It's called from AppClass, ExternalAppClass and
 *      __SendFcgiScript.  This routine is responsible for adding the
 *      new entry to the appClassTable also.
 *
 * Results:
 *      NULL pointer is returned if the class has already been defined
 *      or a valid fast cgi server info pointer.
 *
 * Side effects:
 *      FastCGI server info structure is allocated and initialized.
 *      This includes allocation and initialization of the per 
 *      connection information.
 *
 *----------------------------------------------------------------------
 */

static FastCgiServerInfo *CreateFcgiServerInfo(int numInstances, char *ePath)
{
    FastCgiServerInfo *serverInfoPtr = NULL;
    FcgiProcessInfo *procInfoPtr;
    int i;

    serverInfoPtr = LookupFcgiServerInfo(ePath);
    if(serverInfoPtr != NULL) {
        return NULL;
    }
    /*
     * Create an info structure for the FastCGI server
     */
    serverInfoPtr = (FastCgiServerInfo *) Malloc(sizeof(FastCgiServerInfo));
    DStringInit(&serverInfoPtr->execPath);
    serverInfoPtr->envp = NULL;
    serverInfoPtr->listenQueueDepth = FCGI_DEFAULT_LISTEN_Q;
    serverInfoPtr->numProcesses = numInstances;
    serverInfoPtr->restartDelay = FCGI_DEFAULT_RESTART_DELAY;
    serverInfoPtr->restartOnExit = FALSE;
    serverInfoPtr->numRestarts = 0;
    serverInfoPtr->numFailures = 0;
    serverInfoPtr->ipcAddr = OS_InitIpcAddr();
    serverInfoPtr->directive = APP_CLASS_UNKNOWN;
    DStringInit(&serverInfoPtr->host);
    DStringInit(&serverInfoPtr->bindName);
    serverInfoPtr->port = -1;
    serverInfoPtr->processPriority = FCGI_DEFAULT_PRIORITY;
    serverInfoPtr->listenFd = -1;
    serverInfoPtr->reqRefCount = 0;
    serverInfoPtr->freeOnZero = FALSE;
    serverInfoPtr->affinity = FALSE;
    serverInfoPtr->restartTimerQueued = FALSE;
    serverInfoPtr->keepConnection = FALSE;
    serverInfoPtr->fcgiFd = -1;
    
    /* Dynamic FastCGI applcations */
    serverInfoPtr->totalConnTime = 0;
    serverInfoPtr->smoothConnTime = 0;
    serverInfoPtr->totalQueueTime = 0;
    serverInfoPtr->avgQueueTime = 0;
    
    serverInfoPtr->procInfo = 
      (FcgiProcessInfo *) Malloc(sizeof(FcgiProcessInfo) * numInstances);

    procInfoPtr = serverInfoPtr->procInfo;
    for(i = 0; i < numInstances; i++) {
        procInfoPtr->pid = -1;
        procInfoPtr->listenFd = -1;
        procInfoPtr->fcgiFd = -1;
	procInfoPtr->state = STATE_READY;
        procInfoPtr->ipcAddr = OS_InitIpcAddr();
        procInfoPtr->serverInfoPtr = serverInfoPtr;
        procInfoPtr++;
    }
    serverInfoPtr->next = fastCgiServers;
    fastCgiServers = serverInfoPtr;
    return serverInfoPtr;
}

/*
 *----------------------------------------------------------------------
 *
 * FreeFcgiServerInfo --
 *
 *      This routine frees up all resources associated with a FastCGI
 *      application server.  It's called on error cleanup and as a result
 *      of a shutdown or restart.
 *
 * Results:
 *      FastCgi server and process structures freed.
 *
 * Side effects:
 *      FastCGI info structure is deallocated and unavailable.
 *
 *----------------------------------------------------------------------
 */
static void FreeFcgiServerInfo(FastCgiServerInfo *serverInfoPtr)
{
    FcgiProcessInfo *processInfoPtr;
    int i, numChildren;
    char *lockFileName;
    OS_IpcAddr *ipcAddrPtr;
    char *fname;

    /*
     * Free up process/connection info.
     */
    processInfoPtr = serverInfoPtr->procInfo;
    if(serverInfoPtr->directive == APP_CLASS_DYNAMIC) {
        numChildren = maxClassProcs;
    } else {
        numChildren = serverInfoPtr->numProcesses;
    }

    for (i = 0; i < numChildren; i++, processInfoPtr++) {
        if(processInfoPtr->pid != -1 && processInfoPtr->pid != 0) {
            kill(processInfoPtr->pid, SIGTERM);
            processInfoPtr->pid = -1;
        }
        OS_FreeIpcAddr(processInfoPtr->ipcAddr);
    }

    if (serverInfoPtr->directive == APP_CLASS_DYNAMIC) {
      /*
       * Remove the dead lock file and socket.
       */
      lockFileName = MakeLockFileName(DStringValue(&serverInfoPtr->execPath));
      unlink(lockFileName);
      Free(lockFileName);
      
      ipcAddrPtr = (OS_IpcAddr *)serverInfoPtr->ipcAddr;
      fname = MakeSocketName(DStringValue(&serverInfoPtr->execPath),
			     NULL, -1, &ipcAddrPtr->bindPath, 1);
      /* Remove extraneous digit from end.  XXX why is this necessary?  */
      fname[strlen(fname)-1] = '\0';
      unlink(fname);
      Free(fname);
    }

    /*
     * Clean up server info structure resources.
     */
    OS_FreeIpcAddr(serverInfoPtr->ipcAddr);
    DStringFree(&serverInfoPtr->execPath);
    DStringFree(&serverInfoPtr->host);
    DStringFree(&serverInfoPtr->bindName);
    serverInfoPtr->port = -1;
    serverInfoPtr->directive = APP_CLASS_UNKNOWN;
    if(serverInfoPtr->listenFd != -1) {
        OS_Close(serverInfoPtr->listenFd);
        serverInfoPtr->listenFd = -1;
    }
    Free(serverInfoPtr->procInfo);
    serverInfoPtr->procInfo = NULL;
    if(serverInfoPtr->envp != NULL) {
        OS_EnvironFree(serverInfoPtr->envp);
        serverInfoPtr->envp = NULL;
    }

    /* Dynamic FastCGI applications */
    serverInfoPtr->totalConnTime = 0;
    serverInfoPtr->smoothConnTime = 0;
    serverInfoPtr->totalQueueTime = 0;
    serverInfoPtr->avgQueueTime = 0;

    /*
     * If serverInfoPtr is part of fastCgiServers list, unlink it
     */
    if (serverInfoPtr == fastCgiServers) {
        fastCgiServers = fastCgiServers->next;
    } else {
        FastCgiServerInfo *tmpPtr = fastCgiServers;
        while(tmpPtr->next != NULL && tmpPtr->next != serverInfoPtr) {
            tmpPtr = tmpPtr->next;
        }
        if(tmpPtr->next == serverInfoPtr) {
            tmpPtr->next = serverInfoPtr->next;
        }
    }
    Free(serverInfoPtr);
}

/*
 *----------------------------------------------------------------------
 *
 * CleanupPreviousConfig --
 *
 *      This routine is called by each directive in the module.
 *      If the directive is the first directive in the reading of
 *      a new configuration, the routine cleans up from any previous
 *      reading of a configuration by this process.
 *
 *----------------------------------------------------------------------
 */

static void CleanupPreviousConfig(void)
{
    if(!readingConfig) {
        while(fastCgiServers != NULL) {
            FreeFcgiServerInfo(fastCgiServers);
        }
        readingConfig = TRUE;
    }
}

/*
 *----------------------------------------------------------------------
 *
 * ParseApacheRawArgs --
 *
 * Turns an Apache RAW_ARGS input into argc and argv.
 *
 * Input: rawArgs 
 *      The RAW_ARGS input (everything but the command name.)
 *      Arguments are separated by whitespace (sequences of
 *      space or tab characters.)
 *
 * Results:
 *      Returns argv; assigns argc to *argcPtr.  argv[0]
 *      is NULL; argv[1] is the first argument.
 *
 * Side effects:
 *      If argc > 0 then Mallocs argv and argv[1], which the client
 *      is responsible for freeing.
 *
 *----------------------------------------------------------------------
 */

char **ParseApacheRawArgs(char *rawArgs, int *argcPtr) 
{
    char *input, *p;
    int i;
    int argc = 0;
    char **argv = NULL;

    /*
     * Apache doesn't specify that rawArgs starts with a
     * non-whitespace, so be sure.
     */
    rawArgs += strspn(rawArgs, " \t");
    if(*rawArgs == '\0') {
        goto Done;
    }
    input = Malloc(strlen(rawArgs) + 1);
    strcpy(input, rawArgs);

    /*
     * Make one pass over the input, null-terminating each argument and
     * computing argc.  Then allocate argv, with argc entries.  argc
     * starts at 1 since Apache does not pass the command name with the input.
     */
    p = input;
    argc = 1;
    for(;;) {
        /*
         * *p is a non-whitespace character.  Look for a whitespace character.
         */
        p += strcspn(p, " \t");
        argc++;
        if(*p == '\0') {
            break;
        }
        *p++ = '\0';

        /*
         * Look for a non-whitespace character.
         */
        p += strspn(p, " \t");
        if(*p == '\0') {
            break;
        }
    }
    argv = Malloc(sizeof(char *) * argc);

    /*
     * Make a second pass over the input to fill in argv.
     */
    p = input;
    i = 1;
    for(;;) {
        argv[i++] = p;
        if(i == argc) {
            break;
	}
        p += strlen(p) + 1;
        p += strspn(p, " \t");
    }
  Done:
    *argcPtr = argc;
    return argv;
}

/*
 *----------------------------------------------------------------------
 *
 * ConfigureLocalServer --
 *
 *      Configure a FastCGI server for local communication using 
 *      Unix domain sockets.  This is used by ExternalAppClass directive
 *      to configure connection point for "-socket" option.
 *
 * Results:
 *      0 on successful configure or -1 if there was an error
 *
 * Side effects:
 *      New FastCGI structure is allocated.
 *
 *----------------------------------------------------------------------
 */

static int ConfigureLocalServer(
	char *execPath,
        char *bindPath,
        int affinity,
        int numInstances,
        FastCgiServerInfo *serverInfoPtr)
{
    FcgiProcessInfo *processInfoPtr;
    int i;
    
    serverInfoPtr->affinity = affinity;
    serverInfoPtr->numProcesses = numInstances;

    if(serverInfoPtr->affinity == FALSE) {
        if(OS_CreateLocalIpcAddr(serverInfoPtr->ipcAddr, 
                MakeSocketName, execPath, 
                bindPath, -1, 0) != 0) {
            return -1;
        }
    } else {  
        processInfoPtr = serverInfoPtr->procInfo;
        for(i = 0; i < numInstances; i++) {
            if(OS_CreateLocalIpcAddr(processInfoPtr->ipcAddr, 
                    MakeSocketName, execPath, 
                    bindPath, i+1, 0) != 0) {
                return -1;
            }
            processInfoPtr++;
        }
    }
    return 0;
}

/*
 *----------------------------------------------------------------------
 *
 * ConfigureTCPServer --
 *
 *      Configure a FastCGI server for communication using TCP.  This is 
 *      used by ExternalAppClass directive to configure connection point
 *      for "-host" option.   The remote host is specified as 'host:port', 
 *      as in 'aegean.openmarket.com:666'.
 *
 * Results:
 *      0 on successful configure or -1 if there was an error
 *
 * Side effects:
 *      New FastCGI structure is allocated and modifies hostSpec.
 *
 *----------------------------------------------------------------------
 */

static int ConfigureTCPServer(
        char *hostSpec,
        int affinity,
        int numInstances,
        FastCgiServerInfo *serverInfoPtr) 
{
    FcgiProcessInfo *processInfoPtr;
    struct in_addr host;
    long port;
    char *p, *cvptr;
    int i, numHosts;
    
    /*
     * Parse the host specification string into host and port components.
     */
    p = strchr(hostSpec, ':');
    if(p == NULL) {
        return -1;
    }
    *p++ = '\0';

    if((numHosts = ResolveHostname(hostSpec, &host)) < 0) {
        return -1;
    }

    /*
     * If the address lookup resolves to more than one host, this is
     * an error.  The proper way to handle this is for the creator of
     * the server configuration file to specify the IP address in dotted
     * decimal notation.  This will insure the proper host routing (as
     * long as someone doesn't have multiple machines with the same IP
     * address which is not legal and we can't do anything about that).
     */
    if(numHosts > 1) {
        return -1;
    }
    
    port = strtol(p, &cvptr, 10);
    if(*cvptr != '\0' || port < 1 || port > 65535) {
        return -1;
    }
    
    /*
     * Create an info structure for the Fast CGI server (TCP type).
     */
    DStringAppend(&serverInfoPtr->host, hostSpec, -1);
    serverInfoPtr->port = (int)port;
    serverInfoPtr->affinity = affinity;
    serverInfoPtr->numProcesses = numInstances;
    
    if(serverInfoPtr->affinity == FALSE) {
        OS_CreateInetIpc(serverInfoPtr->ipcAddr, &host, (int)port);
    } else {
        processInfoPtr = serverInfoPtr->procInfo;
        for(i = 0; i < numInstances; i++) {
            OS_CreateInetIpc(processInfoPtr->ipcAddr, &host, (int)(port + i));
            processInfoPtr++;
        }
    }
    return 0;
}

/*
 *----------------------------------------------------------------------
 *
 * AppClassCmd --
 *
 *      Implements the FastCGI AppClass configuration directive.  This
 *      command adds a fast cgi program class which will be used by the
 *      httpd parent to start/stop/maintain fast cgi server apps.
 *
 *      AppClass <exec-path> [-processes N] \
 *               [-restart-delay N] [-priority N] \
 *               [-port N] [-socket sock-name] \
 *               [-initial-env name1=value1] \
 *               [-initial-env name2=value2]
 *
 * Default values:
 *
 * o numProcesses will be set to 1
 * o restartDelay will be set to 5 which means the application will not
 *   be restarted any earlier than 5 seconds from when it was last
 *   invoked.  If the application has been up for longer than 5 seconds
 *   and it fails, a single copy will be restarted immediately.  Other
 *   restarts within that group will be inhibited until the restart-delay
 *   has elapsed.
 * o affinity will be set to FALSE (ie. no process affinity) if not
 *   specified.
 * o if both -socket and -port are omitted, server generates a name for the
 *   socket used in connection.
 *
 * Results:
 *      NULL or an error message.
 *
 * Side effects:
 *      Registers a new AppClass handler for FastCGI.
 *
 *----------------------------------------------------------------------
 */

const char *AppClassCmd(cmd_parms *cmd, void *dummy, char *arg)
{
    int argc;
    char **argv = NULL;
    char *execPath;
    FastCgiServerInfo *serverInfoPtr = NULL;
    int i, n;
    uid_t uid;
    gid_t gid;
    char *cvtPtr;
    char **envHead = NULL;
    char **envPtr;
    int envCount;
    char *namePtr;
    char *valuePtr;
    int numProcesses = 1;
    int restartDelay = FCGI_DEFAULT_RESTART_DELAY;
    int processPriority = FCGI_DEFAULT_PRIORITY;
    int listenQueueDepth = FCGI_DEFAULT_LISTEN_Q;
    char *bindname = NULL;
    int portNumber = -1;  
    int affinity = FALSE;
    char *errMsg = Malloc(1024);

    /*
     * If this is the first call to AppClassCmd since a
     * server restart, clean up structures created by the previous
     * sequence of AppClassCmds.
     */
    CleanupPreviousConfig(); 

    /*
     * Parse the raw arguments into tokens.
     * argv[0] is empty and argv[1] is the exec path.
     * Validate the exec path.
     */
    argv = ParseApacheRawArgs(arg, &argc);
    if(argc < 2) {
        sprintf(errMsg, "AppClass: Too few args\n");
        goto ErrorReturn;
    }

    execPath = argv[1];
    serverInfoPtr = LookupFcgiServerInfo(execPath);
    if(serverInfoPtr != NULL) {
        sprintf(errMsg,
                "AppClass: Redefinition of previously defined class %s\n",
                execPath);
        goto ErrorReturn;
    }

    uid = (user_id == (uid_t) -1)  ? geteuid() : user_id;
#ifndef __EMX__
    gid = (group_id == (gid_t) -1) ? getegid() : group_id;
#else
    gid = (gid_t)-1;
#endif
    if(WS_Access(execPath, NULL, X_OK, uid, gid)) {
        sprintf(errMsg, "AppClass: Could not access file %s\n", execPath);
        goto ErrorReturn;
    }

    /*
     * You'd like to create the server info structure now, but
     * you can't because you don't know numProcesses.  So
     * parse the options now.  Make a conservative over-estimate
     * of the number of -initial-env options so that an environment
     * structure can be allocated now.
     */
    envCount = argc/2 + 1;
    envHead = OS_EnvironInit(envCount);
    envPtr = envHead;
    for(i = 2; i < argc; i++) {
        if((strcmp(argv[i], "-processes") == 0)) {
            if((i + 1) == argc) {
                goto MissingValueReturn;
            }
            i++;
            n = strtol(argv[i], &cvtPtr, 10);
            if(*cvtPtr != '\0' || n < 1 || n > FCGI_DEFAULT_MAX_PROCS) {
                goto BadValueReturn;
            }
            numProcesses = n;
            continue;
        } else if((strcmp(argv[i], "-restart-delay") == 0)) {
            if((i + 1) == argc) {
                goto MissingValueReturn;
            }
            i++;
            n = strtol(argv[i], &cvtPtr, 10);
            if(*cvtPtr != '\0' || n < 0) {
                goto BadValueReturn;
            }
            restartDelay = n;
            continue;
        } else if((strcmp(argv[i], "-priority") == 0)) {
            if((i + 1) == argc) {
                goto MissingValueReturn;
            }
            i++;
            n = strtol(argv[i], &cvtPtr, 10);
            if(*cvtPtr != '\0' || n < 0 || n > 20) {
                goto BadValueReturn;
	    }
            processPriority = n;
	    continue;
	} else if((strcmp(argv[i], "-listen-queue-depth") == 0)) {
	    if((i + 1) == argc) {
                goto MissingValueReturn;
	    }
	    i++;
	    n = strtol(argv[i], &cvtPtr, 10);
	    if(*cvtPtr != '\0' || n < 1) {
                goto BadValueReturn;
            }
            listenQueueDepth = n;
            continue;
        } else if((strcmp(argv[i], "-port") == 0)) {
            if((i + 1) == argc) {
                goto MissingValueReturn;
            }
            i++;
            n = strtol(argv[i], &cvtPtr, 10);
            if(*cvtPtr != '\0' || n < 1) {
                goto BadValueReturn;
            }
            portNumber = n;
            continue;
        } else if((strcmp(argv[i], "-socket") == 0)) {
            if((i + 1) == argc) {
                goto MissingValueReturn;
            }
            i++;
            bindname = argv[i];
            continue;
        } else if((strcmp(argv[i], "-initial-env") == 0)) {
            if((i + 1) == argc) {
                goto MissingValueReturn;
            }
            i++;
            namePtr = argv[i];
            valuePtr = strchr(namePtr, '=');
            if(valuePtr != NULL) {
                *valuePtr = '\0';
                valuePtr++;
            } else {
                goto BadValueReturn;
            }
            OS_EnvString(envPtr, namePtr, valuePtr);
            envPtr++;
            valuePtr--;
            *valuePtr = '=';
            continue;
        } else {
            sprintf(errMsg, "AppClass: Unknown option %s\n", argv[i]);
            goto ErrorReturn;
        }
    } /* for */

    if((bindname != NULL) && (portNumber != -1)) {
        sprintf(errMsg,
                "AppClass: -port and -socket options are mutually exclusive");
        goto ErrorReturn;
    }
    serverInfoPtr = CreateFcgiServerInfo(numProcesses, execPath);
    ASSERT(serverInfoPtr != NULL);
    DStringAppend(&serverInfoPtr->execPath, execPath, -1);
    serverInfoPtr->restartOnExit = TRUE;
    serverInfoPtr->restartDelay = restartDelay;
    serverInfoPtr->processPriority = processPriority;
    serverInfoPtr->listenQueueDepth = listenQueueDepth;
    if(bindname != NULL) {
      DStringAppend(&serverInfoPtr->bindName, bindname, -1);
    }
    serverInfoPtr->port = portNumber;
    serverInfoPtr->envp = envHead;
    serverInfoPtr->directive = APP_CLASS_STANDARD;

    /*
     * Set envHead to NULL so that if there is an error below we don't
     * free the environment structure twice.
     */
    envHead = NULL;

    /*
     * Create an IPC path for the AppClass.
     */
    if(affinity == FALSE) {
        int listenFd;
        if(serverInfoPtr->port == -1) { 
            /* local IPC */
            listenFd = OS_CreateLocalIpcFd(serverInfoPtr->ipcAddr,
                    serverInfoPtr->listenQueueDepth, uid, gid,
                    MakeSocketName, execPath, 
                    bindname, -1, 0);
        } else {
            /* TCP/IP */
            listenFd = OS_CreateRemoteIpcFd(serverInfoPtr->ipcAddr,
                    serverInfoPtr->port, serverInfoPtr->listenQueueDepth);
        }

        if(listenFd < 0) {
            sprintf(errMsg, "AppClass: could not create IPC socket\n");
            goto ErrorReturn;
        }
        serverInfoPtr->listenFd = listenFd;
        /*
         * Propagate listenFd to each process so that process manager
         * doesn't have to understand affinity.
         */
        for(i = 0; i < serverInfoPtr->numProcesses; i++) {
            serverInfoPtr->procInfo[i].listenFd = listenFd;
        }
    }
    Free(argv[1]);
    Free(argv);
    Free(errMsg);
    return NULL;

MissingValueReturn:
    sprintf(errMsg, "AppClass: missing value for %s\n", argv[i]);
    goto ErrorReturn;
BadValueReturn:
    sprintf(errMsg, "AppClass: bad value \"%s\" for %s\n", argv[i], argv[i-1]);
    goto ErrorReturn;
ErrorReturn:
    if(serverInfoPtr != NULL) {
        FreeFcgiServerInfo(serverInfoPtr);
    }
    if(envHead != NULL) {
        OS_EnvironFree(envHead);
    }
    if(argv != NULL) {
        Free(argv[1]);
        Free(argv);
    }
    return errMsg;
}

/*
 *----------------------------------------------------------------------
 *
 * ExternalAppClassCmd --
 *
 *      Implements the FastCGI ExternalAppClass configuration directive.  
 *      This command adds a fast cgi program class which will be used by the
 *      httpd parent to connect to the fastcgi process which is not managed 
 *      by the web server and may be running on the local or remote machine.
 *
 *      ExternalAppClass <name> [-host hostname:port] \
 *                              [-socket socket_path] 
 *
 *
 * Results:
 *      NULL or an error message.
 *
 * Side effects:
 *      Registers a new ExternalAppClass handler for FastCGI.
 *
 *----------------------------------------------------------------------
 */

const char *ExternalAppClassCmd(cmd_parms *cmd, void *dummy, char *arg)
{
    int argc;
    char **argv = NULL;
    char *className = NULL;
    char *hostPort = NULL;
    char *localPath = NULL;
    FastCgiServerInfo *serverInfoPtr = NULL;
    int configResult = -1;
    int i;
    char *errMsg = Malloc(1024);

    /*
     * If this is the first call to ExternalAppClassCmd since a
     * server restart, clean up structures created by the previous
     * sequence of ExternalAppClassCmds.
     */
    CleanupPreviousConfig();

    /*
     * Parse the raw arguments into tokens.
     * argv[0] is empty and argv[1] is the symbolic
     * name of the connection.   Note that this name
     * is not used for anything but the lookup of the
     * proper server.
     */
    argv = ParseApacheRawArgs(arg, &argc);
    if(argc < 3) {
        sprintf(errMsg, "ExternalAppClass: Too few args\n");
        goto ErrorReturn;
    }
    className = argv[1];
    serverInfoPtr = LookupFcgiServerInfo(className);
    if(serverInfoPtr != NULL) {
        sprintf(errMsg,
                "ExternalAppClass: Redefinition of previously \
                defined class %s\n",
                className);
        goto ErrorReturn;
    }

    /* 
     * Parse out the command line arguments.
     */
    for(i = 2; i < argc; i++) {
        if((strcmp(argv[i], "-host") == 0)) {
            if((i + 1) == argc) {
                goto MissingValueReturn;
            }
            i++;
            hostPort = argv[i];
            continue;
        } else if((strcmp(argv[i], "-socket") == 0)) {
            if((i+1) == argc) {
                goto MissingValueReturn;
            }
            i++;
            localPath = argv[i];
            continue;
        } else {
            sprintf(errMsg, "ExternalAppClass: Unknown option %s\n", argv[i]);
            goto ErrorReturn;
        }
      } /* for */
    
    /* 
     * Check out that we do not have any conflicts
     */
    if(((hostPort != NULL) && (localPath != NULL)) ||
        ((hostPort == NULL) && (localPath == NULL))) {
        sprintf(errMsg, "ExternalAppClass: Conflict of arguments -port \
                and -socket.\n");
        goto ErrorReturn;
    }

    /*
     * The following code will have to change when Apache will
     * begin to support connections with affinity.  Note that the
     * className becomes an execPath member of the serverInfo 
     * structure and it used just for lookups.  I also put in values
     * for affinity and numInstances in order to keep most of the
     * common code in sync.
     */
    serverInfoPtr = CreateFcgiServerInfo(1, className);
    ASSERT(serverInfoPtr != NULL);
    DStringAppend(&serverInfoPtr->execPath, className, -1);
    serverInfoPtr->directive = APP_CLASS_EXTERNAL;

    if(hostPort != NULL) {
        configResult = ConfigureTCPServer(hostPort, FALSE,
                                          1, serverInfoPtr);
    } else {
        DStringAppend(&serverInfoPtr->bindName, localPath, -1);
        configResult = ConfigureLocalServer(
		className, localPath, FALSE,
                1, serverInfoPtr);
    }

    if(configResult == 0) {
        return NULL;
    } else {
        sprintf(errMsg, "ExternalAppClass: Unable to configure server\n");
        goto ErrorReturn;
    }

MissingValueReturn:
    sprintf(errMsg, "ExternalAppClass: missing value for %s\n", argv[i]);
    goto ErrorReturn;
#if 0
BadValueReturn:
    sprintf(errMsg, "ExternalAppClass: bad value \"%s\" for %s\n", 
            argv[i], argv[i-1]);
    goto ErrorReturn;
#endif
ErrorReturn:
    if(serverInfoPtr != NULL) {
        FreeFcgiServerInfo(serverInfoPtr);
    }
    if(argv != NULL) {
        Free(argv[1]);
        Free(argv);
    }
    return errMsg;
}

/*
 *----------------------------------------------------------------------
 *
 * FCGIConfigCmd --
 *
 *      Implements the FastCGI FCGIConfig configuration directive.  
 *      This command adds routines to control the execution of the 
 *      dynamic FastCGI processes.  
 *
 *
 *----------------------------------------------------------------------
 */
const char *FCGIConfigCmd(cmd_parms *cmd, void *dummy, char *arg)
{
    int argc;
    char **argv = NULL;
    int i, n;
    char *errMsg = Malloc(1024);
    char *cvtPtr;
    double d;

    /*
     * Parse the raw arguments into tokens.
     * Argument/value pairs start from argv[1],
     * where argv[0] is empty.
     */
    argv = ParseApacheRawArgs(arg, &argc);
    if(argc < 2) {
        sprintf(errMsg, "FCGIConfig: Too few args\n");
        goto ErrorReturn;
    }

    /* 
     * Parse out the command line arguments.
     */
    for(i = 1; i < argc; i++) {
        if((strcmp(argv[i], "-maxProcesses") == 0)) {
            if((i + 1) == argc) {
                goto MissingValueReturn;
            }
            i++;
	    n = strtol(argv[i], &cvtPtr, 10);
	    if(*cvtPtr != '\0' || n < 1 || n > 250) {
                goto BadValueReturn;
            }
	    maxProcs = n;
            continue;
        } else if((strcmp(argv[i], "-minProcesses") == 0)) {
            if((i+1) == argc) {
                goto MissingValueReturn;
            }
            i++;
	    n = strtol(argv[i], &cvtPtr, 10);
	    if(*cvtPtr != '\0' || n < 0 || n > 250) {
                goto BadValueReturn;
            }
	    minProcs = n;
            continue;
        } else if((strcmp(argv[i], "-maxClassProcesses") == 0)) {
            if((i+1) == argc) {
                goto MissingValueReturn;
            }
            i++;
	    n = strtol(argv[i], &cvtPtr, 10);
	    if(*cvtPtr != '\0' || n < 1 || n > 250) {
                goto BadValueReturn;
            }
	    maxClassProcs = n;
            continue;
        } else if((strcmp(argv[i], "-killInterval") == 0)) {
            if((i+1) == argc) {
                goto MissingValueReturn;
            }
            i++;
	    n = strtol(argv[i], &cvtPtr, 10);
	    if(*cvtPtr != '\0' || n < 1) {
                goto BadValueReturn;
            }
	    killInterval = n;
            continue;
        } else if((strcmp(argv[i], "-updateInterval") == 0)) {
            if((i+1) == argc) {
                goto MissingValueReturn;
            }
            i++;
	    n = strtol(argv[i], &cvtPtr, 10);
	    if(*cvtPtr != '\0' || n < 1) {
                goto BadValueReturn;
            }
	    updateInterval = n;
            continue;
        } else if((strcmp(argv[i], "-gainValue") == 0)) {
            if((i+1) == argc) {
                goto MissingValueReturn;
            }
            i++;
	    d = strtod(argv[i], &cvtPtr);
	    if(*cvtPtr != '\0' || d < 0.0 || d > 1.0) {
                goto BadValueReturn;
            }
	    gain = d;
            continue;
        } else if((strcmp(argv[i], "-singleThreshhold") == 0)) {
            if((i+1) == argc) {
                goto MissingValueReturn;
            }
            i++;
	    n = strtol(argv[i], &cvtPtr, 10);
	    if(*cvtPtr != '\0' || n < 1 || n > 100) {
                goto BadValueReturn;
            }
	    threshhold1 = n;
            continue;
        } else if((strcmp(argv[i], "-multiThreshhold") == 0)) {
            if((i+1) == argc) {
                goto MissingValueReturn;
            }
            i++;
	    n = strtol(argv[i], &cvtPtr, 10);
	    if(*cvtPtr != '\0' || n < 1 || n > 100) {
                goto BadValueReturn;
            }
	    threshholdN = n;
            continue;
        } else if((strcmp(argv[i], "-startDelay") == 0)) {
            if((i+1) == argc) {
                goto MissingValueReturn;
            }
            i++;
	    n = strtol(argv[i], &cvtPtr, 10);
	    if(*cvtPtr != '\0' || n < 1) {
                goto BadValueReturn;
            }
	    startProcessDelay = n;
            continue;
        } else if((strcmp(argv[i], "-appConnTimeout") == 0)) {
            if((i+1) == argc) {
                goto MissingValueReturn;
            }
            i++;
	    n = strtol(argv[i], &cvtPtr, 10);
	    if(*cvtPtr != '\0' || n < 1) {
                goto BadValueReturn;
            }
	    appConnTimeout = n;
            continue;
        } else if((strcmp(argv[i], "-processSlack") == 0)) {
            if((i+1) == argc) {
                goto MissingValueReturn;
            }
            i++;
	    n = strtol(argv[i], &cvtPtr, 10);
	    if(*cvtPtr != '\0' || n < 1 || n > 250) {
                goto BadValueReturn;
            }
	    processSlack = n;
            continue;
        } else if((strcmp(argv[i], "-restart") == 0)) {
	    restartDynamic = 1;
            continue;
        } else if((strcmp(argv[i], "-autoUpdate") == 0)) {
	    autoUpdate = 1;
            continue;
        } else {
            sprintf(errMsg, "FCGIConfig: Unknown option %s\n", argv[i]);
            goto ErrorReturn;
        }
    } /* for */
    /* all done */
    Free(argv);
    Free(errMsg);
    return NULL;

MissingValueReturn:
    sprintf(errMsg, "FCGIConfig: missing value for %s\n", argv[i]);
    goto ErrorReturn;
BadValueReturn:
    sprintf(errMsg, "FCGIConfig: bad value \"%s\" for %s\n", 
            argv[i], argv[i-1]);
    goto ErrorReturn;
ErrorReturn:
    if(argv != NULL) {
        Free(argv);
    }
    return errMsg;
}

/*
 *----------------------------------------------------------------------
 *
 * Code related to communication between the FastCGI process manager
 * and the web server in the case of the dynamic FastCGI applications.
 *
 *----------------------------------------------------------------------
 */
/*
 *----------------------------------------------------------------------
 * 
 * LockRegion
 * 
 *      Provide file locking via fcntl(2) function call.  This 
 *      code has been borrowed from Stevens "Advanced Unix 
 *      Programming", page 370.  
 *
 * Inputs:
 *      File descriptor to be locked, offsets within the file.
 *
 * Results:
 *      0 on successful locking, -1 otherwise
 *
 * Side effects:
 *      File pointed to by file descriptor is locked or unlocked.
 *      Provided macros allow for both blocking and non-blocking
 *      behavior.
 *
 *----------------------------------------------------------------------
 */

int LockRegion(int fd, int cmd, int type, off_t offset, int whence, off_t len)
{
    struct flock lock;
    int res;
    
    lock.l_type = type;       /* F_RDLCK, F_WRLCK, F_UNLCK */
    lock.l_start = offset;    /* byte offset, relative to whence */
    lock.l_whence = whence;   /* SEEK_SET, SEET_CUR, SEEK_END */
    lock.l_len = len;         /* # of bytes, (0 indicates to EOF) */

    /* Don't be fooled into thinking we've set a lock when we've
       merely caught a signal.  */
    while ((res = fcntl(fd, cmd, &lock)) == -1 && errno == EINTR)
      ;
    return res;
}
/* Ways to lock an entire file... */

/* Shared locks: allows other shared locks, but no exclusive locks.  */
/* Set a shared lock, no wait, failure->errno==EACCES.  */
#define ReadLock(fd) LockRegion(fd, F_SETLK, F_RDLCK, 0, SEEK_SET, 0)
/* Set a shared lock, wait until you have it.  */
#define ReadwLock(fd) LockRegion(fd, F_SETLKW, F_RDLCK, 0, SEEK_SET, 0)

/* Exclusive locks: allows no other locks.  */
/* Set an exclusive lock, no wait, failure->errno==EACCES.  */
#define WriteLock(fd) LockRegion(fd, F_SETLK, F_WRLCK, 0, SEEK_SET, 0)
/* Set a shared lock, wait until you have it.  */
#define WritewLock(fd) LockRegion(fd, F_SETLKW, F_WRLCK, 0, SEEK_SET, 0)

/* Remove a shared or exclusive lock, no wait, failure->errno=EACCES.  */
#define Unlock(fd) LockRegion(fd, F_SETLK, F_UNLCK, 0, SEEK_SET, 0)

/****************************************************************************/
/*
 * Opcodes for Server/ProcMgr communication
 */
#define PLEASE_START 49        /* start dynamic application */
#define CONN_TIMEOUT 50        /* start another copy of application */
#define REQ_COMPLETE 51        /* do some data analysis */
/*
 *----------------------------------------------------------------------
 * 
 * AddNewRecord
 * 
 *      Construct and add new record to mbox.
 *
 * Results:
 *      -1 on error, number of appended bytes otherwise.
 *
 * Side effects:
 *      Mbox is appended.
 *
 *----------------------------------------------------------------------
 */
#ifdef BUFSIZ
#define TMP_BUFSIZ (min(BUFSIZ, 512))
#else
#define TMP_BUFSIZ (512)
#endif

int AddNewRecord(char id, char* execPath, 
        unsigned long qsecs, unsigned long ctime, unsigned long now)
{
    int fd, size, status;
    char buf[TMP_BUFSIZ];
    
    memset(buf, 0, TMP_BUFSIZ);
    switch(id) {
        case PLEASE_START:
                sprintf(buf, "%c %s\n",
                id, execPath);
                break;
        case CONN_TIMEOUT: 
                sprintf(buf, "%c %s %lu\n",
                id, execPath, qsecs);
                break;
        case REQ_COMPLETE:  
                sprintf(buf, "%c %s %lu %lu %lu\n",
                id, execPath, qsecs, ctime, now);
                break;
    }

    /* figure out how big the buffer is */
    size = (strchr((const char *)buf, '\n')-buf)+1;
    ASSERT(size>0);

    if((fd = open(mbox, O_WRONLY|O_APPEND))<0) {
        return (-1);
    }
    WritewLock(fd);
    if(lseek(fd, 0, SEEK_END)<0) {
        status = -1;
    }
    if(write(fd, (const void *)buf, size)<size) {
        status = -1;
    } else {
        status = size;
    }
    Unlock(fd);
    close(fd);
    return (status);
}

/*
 *----------------------------------------------------------------------
 * 
 * RemoveRecords
 * 
 *      Removes the records from the mbox and decodes them.
 *      We also update the data structures to reflect the changes.
 *
 * Results:
 *      -1 on error, otherwise number of processed records
 *
 * Side effects:
 *      Mbox is truncated.  
 *
 *----------------------------------------------------------------------
 */

int RemoveRecords(FILE *errorLogFile)
{
    FastCgiServerInfo *s;
    OS_IpcAddr *ipcAddrPtr = NULL;
    struct stat statbuf;
    int recs = 0, fd, i;
    char *buf=NULL, opcode;
    char *lockFileName=NULL;
    char *ptr1=NULL, *ptr2=NULL;
    char execName[TMP_BUFSIZ];
    unsigned long qsec = 0, ctime = 0; /* microseconds spent waiting for the
					* application, and spent using it */
    time_t now = time(NULL);
    int listenFd;
    
    /* Obtain the data from the mbox file */
    if((fd = open(mbox, O_RDWR))<0) {
        fprintf(errorLogFile,
                "[%s] mod_fastcgi: Unable to open mbox\n", get_time());
        fflush(errorLogFile);
        return -1;
    }
    WritewLock(fd);
    if(fstat(fd, &statbuf)<0) {
        fprintf(errorLogFile, "errno = %d\n", (errno));
        fprintf(errorLogFile,
                "[%s] mod_fastcgi: Unable to fstat() mbox\n", get_time());
        recs = -1;
        goto NothingToDo;
    }
    buf = Malloc(statbuf.st_size+1);
    if(statbuf.st_size==0) {
        recs = 0;
        goto NothingToDo;
    }
    if(read(fd, (void *)buf, statbuf.st_size)<statbuf.st_size) {
        fprintf(errorLogFile,
                "[%s] mod_fastcgi: Read failed for mbox\n", get_time());
        recs = -1;
	goto NothingToDo;
    }
    if(ftruncate(fd, 0)<0) {
        fprintf(errorLogFile,
                "[%s] mod_fastcgi: Unable to ftruncate() mbox\n", get_time());
        recs = -1;
	goto NothingToDo;
    }
    recs = 1;
NothingToDo:
    Unlock(fd);
    close(fd);
    if(recs<0) {
        goto CleanupReturn;
    } 

    /* 
     * To prevent the idle application from running indefinitely, we 
     * check the timer and if it is expired, we recompute the values
     * for each running application class.  Then, when REQ_COMPLETE
     * message is recieved, only updates are made to the data structures.
     */
    if(lastAnalyze == 0) {
        lastAnalyze = now;
    }
    if((long)(now-lastAnalyze)>=updateInterval) {
        for(s=fastCgiServers;s!=NULL;s=s->next) {
	    /* XXX what does this adjustment do? */
	    lastAnalyze += (((long)(now-lastAnalyze)/updateInterval)*updateInterval);
	    s->smoothConnTime = (1.0-gain)*s->smoothConnTime+
	        gain*s->totalConnTime;
	    s->totalConnTime = ctime;
	    s->totalQueueTime = qsec;
	}
    }
    if(recs==0) {
        goto CleanupReturn;
    }

    /* Update data structures for processing */
    for (ptr1 = buf; ptr1 != NULL; ptr1 = ptr2) {
        if((ptr2 = strchr(ptr1, '\n'))!=NULL) {
	    *(ptr2) = '\0';
	    ptr2++;
	}
	opcode = *ptr1;
	switch (opcode) {
	    case PLEASE_START:
		sscanf(ptr1, "%c %s\n", &opcode, execName);
		break;
	    case CONN_TIMEOUT:
		sscanf(ptr1, "%c %s %lu\n", &opcode, execName, &qsec);
		break;
	    case REQ_COMPLETE:
		sscanf(ptr1, "%c %s %lu %lu %lu\n", &opcode, execName,
			&qsec, &ctime, &now);
		break;
	    default:
		goto CleanupReturn;
		break;
	}
	s = LookupFcgiServerInfo(execName);
 	if(s==NULL) {
	    s = CreateFcgiServerInfo(maxClassProcs, execName);
	    DStringAppend(&s->execPath, execName, -1);
	    s->numProcesses = 0;
	    s->restartTime = 0;            
	    s->directive = APP_CLASS_DYNAMIC;
	    /* create a socket file for the app */
	    ipcAddrPtr = (OS_IpcAddr *) OS_InitIpcAddr();
	    listenFd = OS_CreateLocalIpcFd((OS_IpcAddress *)ipcAddrPtr, 
		    FCGI_DEFAULT_LISTEN_Q, 
		    (user_id == (uid_t) -1)  ? geteuid() : user_id,
#ifndef __EMX__
		    (group_id == (gid_t) -1) ? getegid() : group_id,
#else
		    (gid_t)-1,
#endif
		    MakeSocketName, execName, 
		    NULL, -1, 1);
	    if(listenFd<0) {
		fprintf(errorLogFile, "Unable to create a socket for %s\n",
			execName);
	    } else {
		s->listenFd = listenFd;
		for(i=0;i<maxClassProcs;i++) {
		    s->procInfo[i].listenFd = listenFd;
		}
	    }
	    OS_FreeIpcAddr(ipcAddrPtr);
	    /* don't forget to create a lock file for this app */
	    lockFileName = MakeLockFileName(execName);
	    fd = open(lockFileName, O_WRONLY | O_CREAT | O_TRUNC, 
		    S_IRUSR | S_IWUSR);
	    ASSERT(fd>0);
	    close(fd);
	    free(lockFileName);
	} else {
	    if(opcode==PLEASE_START) {
	      if (autoUpdate) {
		  /* Check to see if the binary has changed.  If so,
		   * kill the FCGI application processes, and 
		   * restart them.
		   */
		  struct stat stbuf;
		  int i, numChildren;
		  if ((stat(execName, &stbuf)==0) &&
		      (stbuf.st_mtime > s->restartTime)) {
		    /* kill old server(s) */
		    if (s->directive == APP_CLASS_DYNAMIC) {
		      numChildren = maxClassProcs;
		    } else {
		      numChildren = s->numProcesses;
		    }
		    for (i = 0; i < s->numProcesses; i++) {
		      kill(s->procInfo[i].pid, SIGTERM);
		    }
		    fprintf(errorLogFile,
			    "mod_fastcgi: binary %s modified, restarting FCGI app server\n",
			    execName);
		  }
		  if (restartDynamic) {
		    /* don't worry about restarting the processes after
		     * killing them.  We'll restart them after getting
		     * the SIGCHLD because we're restarting dynamic
		     * proceses automatically.
		     */
		    continue;
		  } else {
		    /* we need to restart this process now.  Don't do a
		     * continue here, and we'll restart it below.
		     */
		  }
		} else {
		  /* we've been asked to start a process--only start
		   * it if we're not already running at least one
		   * instance.
		   */
		  int count = 0;
		  int numChildren;
 
		  /* see if any instances of this app are running */
		  if (s->directive == APP_CLASS_DYNAMIC) {
		    numChildren = maxClassProcs;
		  } else {
		    numChildren = s->numProcesses;
		  }

		  for (i = 0; i < numChildren; i++) {
		    if (s->procInfo[i].state == STATE_STARTED)
		      count++;
		  }
		  /* if already running, don't start another one */
		  if (count > 0) {
		    continue;
		  }
		}
	    }
	}
	switch (opcode) {
	    case PLEASE_START:
	    case CONN_TIMEOUT:
		if((s->numProcesses+1)>maxClassProcs) {
		    /* Can't do anything here, log error */
		    fprintf(errorLogFile,
			    "[%s] mod_fastcgi: Exceeded maxClassProcs\n", 
			    get_time());
		    continue;
		}
		if((globalNumInstances+1)>maxProcs) {
		    /* 
		     * Extra instances should have been 
		     * terminated beforehand, probably need 
		     * to increase ProcessSlack parameter 
		     */
		    fprintf(errorLogFile,
			    "[%s] mod_fastcgi: Exceeded maxProcs\n", 
			    get_time());
		    continue;
		}
		/* find next free slot */
		for(i=0;i<maxClassProcs;i++) {
		    if((s->procInfo[i].pid == -1) &&
			   ((s->procInfo[i].state == STATE_READY) ||
			    (s->procInfo[i].state == STATE_NEEDS_STARTING) ||
			    (s->procInfo[i].state == STATE_KILLED)))
		      break;
		}
		ASSERT(i<maxClassProcs);
		s->procInfo[i].state = 
			STATE_NEEDS_STARTING;
		break;
	   case REQ_COMPLETE:
		s->totalConnTime += ctime;
		s->totalQueueTime += qsec;
		break;
	}
    }
    
CleanupReturn:
    if (buf!=NULL) {
        Free(buf);
	buf = NULL;
    }
    fflush(errorLogFile);
    return (recs);
}
#undef TMP_BUFSIZ


/* Information about a process we are doing a blocking kill of.  */
struct FuncData {
    char *lockFileName;  /* name of the lock file to lock */
    pid_t pid;           /* process to issue SIGTERM to   */
};

/*
 *----------------------------------------------------------------------
 * 
 * BlockingKill
 * 
 *      Block on the lock file until it is available, and then
 *      issue a kill signal to the corresponding application.
 *      Since this function is executed in the child process, 
 *      _exit() is called upon completion.
 *  
 * Inputs
 *      Pointer to the data structure containing a process id to 
 *      issue a signal to and the full pathname to the lockfile 
 *      that needs to be locked before the issue of the signal.
 *
 * Notes
 *      Memory is allocated by the caller, but is freed by this
 *      function.
 *
 *----------------------------------------------------------------------
 */

void BlockingKill(void *data)
{
    struct FuncData *funcData = (struct FuncData *)data;
    int lockFd;

    ASSERT(funcData->lockFileName);
    if((lockFd = open(funcData->lockFileName, O_RDWR))<0) {
        /* There is something terribly wrong here */
    } else {
        if(WritewLock(lockFd)<0) {
	    /* This is a major problem */
	} else {
	    kill(funcData->pid, SIGTERM);
	    Unlock(lockFd);
	}
    }
    /* exit() may flush stdio buffers inherited from the parent. */
    _exit(0);
}

/*
 *----------------------------------------------------------------------
 * 
 * KillDynamicProcs
 * 
 *      Implement a kill policy for the dynamic FastCGI applications.
 *      We also update the data structures to reflect the changes.
 *
 * Side effects:
 *      Processes are marked for deletion possibly killed.
 *
 *----------------------------------------------------------------------
 */

void KillDynamicProcs()
{
    FastCgiServerInfo *s;
    struct FuncData *funcData = NULL;
    time_t now = time(NULL);
    float connTime;		/* server's smoothed running time, or
				 * if that's 0, the current total */
    float totalTime;		/* maximum number of microseconds that all
				 * of a server's running processes together
				 * could have spent running since the
				 * last check */
    float loadFactor;		/* percentage, 0-100, of totalTime that
				 * the processes actually used */
    int i, victims = 0;
    char *lockFileName;
    int lockFd;
    pid_t pid;

    /* pass 1 - locate and mark all victims */
    for(s=fastCgiServers;  s!=NULL; s=s->next) {
	/* Only kill dynamic apps */
	if (s->directive != APP_CLASS_DYNAMIC)
	    continue;

        /* If the number of non-victims is less than or equal to
	   the minimum that may be running without being killed off,
	   don't select any more victims.  */
        if((globalNumInstances-victims)<=minProcs) {
	    break;
	}
	connTime = s->smoothConnTime ? s->smoothConnTime : s->totalConnTime;
        totalTime = (s->numProcesses)*(now-epoch)*1000000 + 1;
	/* XXX producing a heavy load with one client, I haven't been
	   able to achieve a loadFactor greater than 0.5.  Perhaps this
	   should be scaled up by another order of magnitude or two.  */
	loadFactor = connTime/totalTime*100.0;
	if(((s->numProcesses>1) && 
	        (((s->numProcesses/(s->numProcesses-1))*loadFactor)
		 <threshholdN)) ||
	        ((s->numProcesses==1) &&
		    (loadFactor<threshhold1))) {
	    for(i=0;i<maxClassProcs;i++) {
	        /* if need to kill extra instance and have one that
		 * is not started yet, do not start it and skip */
	        if(s->procInfo[i].state == STATE_NEEDS_STARTING) {
		    s->procInfo[i].state = STATE_READY;
		    victims++;
		    break;		
		}
	        if(s->procInfo[i].state == STATE_STARTED) {
		    s->procInfo[i].state = STATE_VICTIM;
		    victims++;
		    break;
		}
	    }
	}
    }
    /* pass 2 - kill procs off */
    for(s=fastCgiServers; s!=NULL; s=s->next) {
	/* Only kill dynamic apps */
	if (s->directive != APP_CLASS_DYNAMIC)
	    continue;

        for(i=0;i<maxClassProcs;i++) {
	    if(s->procInfo[i].state == STATE_VICTIM) {
	        lockFileName = MakeLockFileName(DStringValue(&s->execPath));
		if((lockFd = open(lockFileName, O_RDWR))<0) {
		    /* 
		     * If we need to kill an application and the
		     * corresponding lock file does not exist, then
		     * that means we are in big trouble here 
		     */
		    Free(lockFileName);
		    continue;
		}
		if(WriteLock(lockFd)<0) {
		    /*
		     * Unable to lock the lockfile, indicative 
		     * of WS performing operation with the given
		     * application class.  The simplest solution
		     * is to spawn off another process and block
		     * on lock to kill it.  This is under assumptions
		     * that fork() is not very costly and this 
		     * situation occurs very rarely, which it should
		     */
		    funcData = Malloc(sizeof(struct FuncData));
		    funcData->lockFileName = lockFileName;
		    funcData->pid = s->procInfo[i].pid;
		    /* 
		     * We can not call onto spawn_child() here
		     * since we are completely disassociated from
		     * the web server, and must do process management
		     * directly.
		     */
		    if((pid=fork())<0) {
			close(lockFd);
			Free(funcData->lockFileName);
			Free(funcData);
			return;
		    } else if(pid==0) {
		        /* child */
		        BlockingKill(funcData);
		    } else {
		        /* parent */
			close(lockFd);
			Free(funcData->lockFileName);
			Free(funcData);
		    }
		} else {
		    kill(s->procInfo[i].pid, SIGTERM);
		    Unlock(lockFd);
		    close(lockFd);
		    Free(lockFileName);
		    break;
	        }
	    } 
	}
    }
}

/*
 *----------------------------------------------------------------------
 *
 * Code related to the FastCGI process manager.
 *
 *----------------------------------------------------------------------
 */

/*
 *----------------------------------------------------------------------
 * 
 * FastCgiProcMgr
 * 
 *      The FastCGI process manager, which runs as a separate
 *      process responsible for:
 *        - Starting all the FastCGI proceses.
 *        - Restarting any of these processes that die (indicated
 *          by SIGCHLD).
 *        - Catching SIGTERM and relaying it to all the FastCGI
 *          processes before exiting.
 *
 * Inputs:
 *      Uses global variable fastCgiServers.
 *
 * Results:
 *      Does not return.
 *
 * Side effects:
 *      Described above.
 *
 *----------------------------------------------------------------------
 */
static int caughtSigTerm = FALSE;
static int caughtSigChld = FALSE;
static int caughtSigUsr2 = FALSE;
static char *errorLogPathname = NULL;
static sigset_t signalsToBlock;

static FILE *FastCgiProcMgrGetErrLog(void)
{
    FILE *errorLogFile = NULL;
    if(errorLogPathname != NULL) {
        /*
         * errorLogFile = fopen(errorLogPathname, "a"),
         * but work around faulty implementations of fopen (SunOS)
         */
        int fd = open(errorLogPathname, O_WRONLY | O_APPEND | O_CREAT,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
        if(fd >= 0) {
            errorLogFile = fdopen(fd, "a");
        }
    }
    if(errorLogFile == NULL) {
        errorLogFile = fopen("/dev/null", "a");
    }
    return errorLogFile;
}

static void FastCgiProcMgrSignalHander(int signo)
{
    if(signo == SIGTERM) {
        caughtSigTerm = TRUE;
    } else if(signo == SIGCHLD) {
        caughtSigChld = TRUE;
    } else if(signo == SIGUSR2 || signo == SIGALRM) {
        caughtSigUsr2 = TRUE;
    }
}

static int CaughtSigTerm(void)
{
    int result;

    /*
     * Start of critical region for caughtSigTerm
     */
    sigprocmask(SIG_BLOCK, &signalsToBlock, NULL);
    result = caughtSigTerm;
    sigprocmask(SIG_UNBLOCK, &signalsToBlock, NULL);

    /*
     * End of critical region for caughtSigTerm
     */
    return result;
}

void FastCgiProcMgr(void *data)
{
    FastCgiServerInfo *s, *tmp;
    int i;
    int status, callWaitPid, callDynamicProcs;
    sigset_t sigMask;
    FILE *errorLogFile = FastCgiProcMgrGetErrLog();

    /*
     * If the Apache parent process is running as root,
     * consider reducing privileges now.
     */
    if(geteuid() == 0 && setuid(user_id) == -1) {
        fprintf(errorLogFile,
                "[%s] mod_fastcgi: Unable to change uid, exiting\n",
              get_time());
        fflush(errorLogFile);
        exit(1);
    }

    /* 
     * Create mbox file now, so we won't have to check for
     * its existence later on during processing 
     */
    
    /*
     * Set up to handle SIGTERM, SIGCHLD, and SIGALRM.
     */
    sigemptyset(&signalsToBlock);
    sigaddset(&signalsToBlock, SIGTERM);
    sigaddset(&signalsToBlock, SIGCHLD);
    sigaddset(&signalsToBlock, SIGALRM);
    sigaddset(&signalsToBlock, SIGUSR2);
    sigprocmask(SIG_BLOCK, NULL, &sigMask);
    sigdelset(&sigMask, SIGTERM);
    sigdelset(&sigMask, SIGCHLD);
    sigdelset(&sigMask, SIGALRM);
    sigdelset(&sigMask, SIGUSR2);
    ASSERT(OS_Signal(SIGTERM, FastCgiProcMgrSignalHander) != SIG_ERR);
    ASSERT(OS_Signal(SIGCHLD, FastCgiProcMgrSignalHander) != SIG_ERR);
    ASSERT(OS_Signal(SIGALRM, FastCgiProcMgrSignalHander) != SIG_ERR);
    ASSERT(OS_Signal(SIGUSR2, FastCgiProcMgrSignalHander) != SIG_ERR);
 
    /*
     * s->procInfo[i].pid == 0 means we've never tried to start this one.
     */
    for(s = fastCgiServers; s != NULL; s = s->next) {
        s->restartTime = 0;
        for(i = 0; i < s->numProcesses; i++) {
            s->procInfo[i].pid = 0;
	    s->procInfo[i].state = STATE_NEEDS_STARTING;
	}
    }
    
    /*
     * Loop until SIGTERM
     */
    for (;;) {
        time_t now;
        int sleepSeconds = min(killInterval, updateInterval);
        pid_t childPid;
        int waitStatus;
	int numChildren;

	/* 
	 * If there is no parent process, then the Apache has
	 * terminated or restarted, so perform the cleanup
	 */
	if(1==getppid()) {
	    goto ProcessSigTerm;
	}

        /*
         * Examine each configured AppClass for a process that needs
         * starting.  Compute the earliest time when the start should
         * be attempted, starting it now if the time has passed.  Also,
         * remember that we do NOT need to restart externally managed
         * FastCGI applications.
         */
        for(s = fastCgiServers; s != NULL; s = s->next) {
            if(s->directive == APP_CLASS_EXTERNAL) {
                continue;
            }
	    if(s->directive == APP_CLASS_DYNAMIC) {
	        numChildren = maxClassProcs;
	    } else {
	        numChildren = s->numProcesses;
	    }
            for(i = 0; i < numChildren; i++) {
                if((s->procInfo[i].pid <= 0) && 
		        (s->procInfo[i].state == STATE_NEEDS_STARTING)) {
                    time_t restartTime = s->restartTime + s->restartDelay;
                    time_t now = time(NULL);
		    /* start dynamic apps immediately */
		    if(s->directive == APP_CLASS_DYNAMIC) {
		        restartTime = now;
		    }
                    if(s->procInfo[i].pid == 0 || restartTime <= now) {
                        int restart = (s->procInfo[i].pid < 0);
                        if(restart) {
                            s->numRestarts++;
		        }
                        s->restartTime = now;
                        if(CaughtSigTerm()) {
                            goto ProcessSigTerm;
			}
                        status = OS_ExecFcgiProgram(
                                &s->procInfo[i].pid,
                                s->procInfo[i].listenFd,
                                s->processPriority,
                                DStringValue(&s->execPath),
                                s->envp,
				FastCgiProcMgrGetErrLog);
                        if(status != 0) {
			    fprintf(errorLogFile,
                                    "[%s] mod_fastcgi: AppClass %s"
                                    " fork failed, errno = %s.\n",
                                    get_time(),
                                    DStringValue(&s->execPath), 
                                    strerror(errno));
                            fflush(errorLogFile);
			    /* do not restart failed dynamic apps */
			    if(s->directive != APP_CLASS_DYNAMIC) {
                                sleepSeconds = min(sleepSeconds,
                                        max(s->restartDelay,
                                            FCGI_MIN_EXEC_RETRY_DELAY));
			    } else {
			        s->procInfo[i].state = STATE_READY;
			    }
                            ASSERT(s->procInfo[i].pid < 0);
                            break;
			}
			s->numProcesses++;
			globalNumInstances++;
			s->procInfo[i].state = STATE_STARTED;
                        if(restart) {
                            fprintf(errorLogFile,
                                    "[%s] mod_fastcgi: AppClass %s"
                                    " restarted with pid %d.\n",
                                    get_time(),
                                    DStringValue(&s->execPath), 
                                    (int)s->procInfo[i].pid);
                            fflush(errorLogFile);
			}
                        ASSERT(s->procInfo[i].pid > 0);
		    } else {
                        sleepSeconds = min(sleepSeconds, restartTime - now);
		    }
		}
	    }
	}
 
	/*
         * Start of critical region for caughtSigChld and caughtSigTerm.
         */
        sigprocmask(SIG_BLOCK, &signalsToBlock, NULL);
        if(caughtSigTerm) {
            goto ProcessSigTerm;
	}
        if((!caughtSigChld) && (!caughtSigUsr2)) {
            /*
             * Enable signals and wait.  The call to sigsuspend
             * breaks the critical region into two, so caughtSigChld
             * may have a new value after the wait.
             */
            ASSERT(sleepSeconds > 0);
            alarm(sleepSeconds);
            sigsuspend(&sigMask);
	    alarm(0);
	}
        callWaitPid = caughtSigChld;
        caughtSigChld = FALSE;
	callDynamicProcs = caughtSigUsr2;
	caughtSigUsr2 = FALSE;
        sigprocmask(SIG_UNBLOCK, &signalsToBlock, NULL);

        /*
         * End of critical region for caughtSigChld and caughtSigTerm.
         */

	/* 
	 * Dynamic fcgi process management 
	 */
	if((callDynamicProcs) || (!callWaitPid)) {
	    RemoveRecords(errorLogFile);
	    now = time(NULL);
	    if(epoch == 0) {
	        epoch = now;
	    }
	    if(((long)(now-epoch)>=killInterval) ||
	            ((globalNumInstances+processSlack)>=maxProcs)) {
	        KillDynamicProcs();
	        epoch = now;
	    }
	}

        if(!callWaitPid) {
            continue;
	}

        /*
         * We've caught SIGCHLD, so poll for signal notifications
         * using waitpid.  If a child has died, write a log message
         * and update the data structure so we'll restart the child.
	 *
	 * If the last instance of the dynamic AppClass has terminated,
	 * free up any memory that was associated with it.
         */
        for (;;) {
            if(CaughtSigTerm()) {
                goto ProcessSigTerm;
	    }
            childPid = waitpid(-1, &waitStatus, WNOHANG);
            if(childPid == -1 || childPid == 0) {
                break;
	    }
            for(s = fastCgiServers; s != NULL; s = s->next) {
                if(s->directive == APP_CLASS_EXTERNAL) {
                    continue;
                }
		if(s->directive == APP_CLASS_DYNAMIC) {
		    numChildren = maxClassProcs;
		} else {
		    numChildren = s->numProcesses;
		}
                for(i = 0; i < numChildren; i++) {
                    if(s->procInfo[i].pid == childPid) {
                        goto ChildFound;
		    }
	        }
	    }
	    /*
	     * If we get to this point, we have detected the
	     * termination of the process that was spawned off by
	     * the process manager to do a blocking kill above.
	     */
	    continue;
	  ChildFound:
            s->procInfo[i].pid = -1;

	    /* restart static apps */
	    if(s->directive == APP_CLASS_STANDARD) {
	        s->procInfo[i].state = STATE_NEEDS_STARTING;
	        s->numFailures++;
	    } else {
	        if(s->procInfo[i].state == STATE_VICTIM) {
		    s->procInfo[i].state = STATE_KILLED;
		    s->numProcesses--;
		    globalNumInstances--;
		    continue;
		} else {
		    /* 
		     * dynamic app dies when it shoudn't have.
		     */
		    s->numProcesses--;
		    globalNumInstances--;
		    if (restartDynamic) {
		      s->procInfo[i].state = STATE_NEEDS_STARTING;
		      s->restartDelay = s->numFailures;
		      if (s->restartDelay > 10)
			s->restartDelay = 10;
		      s->numFailures++;
		    } else {
		      s->procInfo[i].state = STATE_READY;
		    }
		}
	    }

            if(WIFEXITED(waitStatus)) {
                fprintf(errorLogFile,
                        "[%s] mod_fastcgi: AppClass %s pid %d terminated"
                        " by calling exit with status = %d.\n",
                        get_time(), DStringValue(&s->execPath), (int)childPid,
                        WEXITSTATUS(waitStatus));
	    } else {
                ASSERT(WIFSIGNALED(waitStatus));
                fprintf(errorLogFile,
                        "[%s] mod_fastcgi: AppClass %s pid %d terminated"
                        " due to uncaught signal %d.\n",
                        get_time(), DStringValue(&s->execPath), (int)childPid,
                        WTERMSIG(waitStatus));
	    }
            fflush(errorLogFile);
        } /* for (;;) */

	for(s=fastCgiServers;s!=NULL;) {
	    if(s->directive == APP_CLASS_DYNAMIC && s->numProcesses == 0) {
	        numChildren = 0;
		for (i = 0; i < maxClassProcs; i++) {
		  if (s->procInfo[i].state == STATE_NEEDS_STARTING)
		    numChildren++;
		}
	        if(numChildren == 0) {
		    tmp=s->next;
		    FreeFcgiServerInfo(s);
		    s=tmp;
		    continue;
		}
	    }
	    s=s->next;
	}
    } /* for (;;) */

ProcessSigTerm:
    /*
     * Kill off the children, then exit.
     */
    while(fastCgiServers != NULL) {
        FreeFcgiServerInfo(fastCgiServers);
    }
    exit(0);
}

/*
 *----------------------------------------------------------------------
 * 
 * FCGIProcMgrBoot
 *
 *      The reason behind this function is to separate any dependencies
 *      between the FCGI process manager and the Apache server.  Thus, 
 *      when the Apache decides to reboot, there will be sufficient time
 *      for the process manager to terminate all running fastcgi apps.
 *      It works as follows:  apache spawns another copy of itself which
 *      will execute this function (basically doing nothing).  This 
 *      function will in turn fork off the process manager (not using
 *      any Apache's calls).  This way, when the Apache will need to 
 *      terminate, it will issue a SIGKILL to this function and will 
 *      collect it, so that we don't have any zombies.  The real process
 *      manager will see that it has no parent process, so it will calmly
 *      terminate all fcgi applications and will terminate, and will 
 *      subsequently be collected by the init process.
 *
 *----------------------------------------------------------------------
 */
static pid_t procMgr = -1;
int FCGIProcMgrBoot(void *data)
{
    int n;
    char buf[IOBUFSIZE];

/*    block_alarms();*/
    if((procMgr=fork())<0) {
        /* error */
        return -1;
    } else if(procMgr==0) {
        /* child */
        FastCgiProcMgr(data);
    } else {
        /* parent */
/*        unblock_alarms();*/
	memset(buf, 0, IOBUFSIZE);
	sprintf(buf, "%ld", procMgr);
	do {
	    n = write(STDOUT_FILENO, buf, IOBUFSIZE);
	} while (((n==-1) || (n==0)) && (errno==EINTR));
        while(1) {
	    sleep(128);
	}
    }
    return (0);
}

/*
 *----------------------------------------------------------------------
 * 
 * DoesAnyFileExist --
 *
 *      Check if the file is present in the file system in the
 *      directory specified by ipcDynamicDir.  Also check that
 *      a given filename is of the given type, such as regular or
 *      socket (FIFO).
 *
 * Results:
 *      1 if file exists, 0 if not, -1 on error
 *
 *----------------------------------------------------------------------
 */
#define FILETYPE_SOCKET  0
#define FILETYPE_REGULAR 1

int DoesAnyFileExist(char *fileName, int fileType)
{
    struct stat statBuf;
    int result = 0;

    if (stat(fileName, &statBuf)<0) {
      return(0);
    }
    switch (fileType) {
    case FILETYPE_SOCKET:
      if(S_ISFIFO(statBuf.st_mode)) {
	result = 1;
      } else {
	result = 0;
      }
      break;
    case FILETYPE_REGULAR:
      if(S_ISREG(statBuf.st_mode)) {
	result = 1;
      } else {
	result = 0;
      }
      break;
    default: 
      result = (-1);
      break;
    }
    return (result);
}
#define DoesLockExist(a) DoesAnyFileExist(a, FILETYPE_REGULAR)
#define DoesFileExist(a) DoesAnyFileExist(a, FILETYPE_REGULAR)
#define DoesSocketExist(a) DoesAnyFileExist(a, FILETYPE_SOCKET)

/*
 *----------------------------------------------------------------------
 * 
 * ModFastCgiInit
 *
 *      An Apache module initializer, called by the Apache core
 *      after reading the server config.
 *
 *      Start the process manager no matter what, since there may be a 
 *      request for dynamic FastCGI applications without any being 
 *      configured as static applications.  Also, check for the existence
 *      and create if necessary a subdirectory into which all dynamic
 *      sockets will go.
 *
 *----------------------------------------------------------------------
 */

extern int standalone;
static int restarts = 0;
void ModFastCgiInit(server_rec *s, pool *p)
{
    FILE *fp=NULL;
    char *ptr, buf[IOBUFSIZE];
    int n;
    uid_t uid;
    gid_t gid;

    /* 
     * This hack will prevent the starting of the process manager
     * the first time Apache reads its configuration files.
     */
    if((restarts==0)&&(standalone==1)) {
        restarts++;
	readingConfig = FALSE;
	return;
    }

    if(s->error_fname != NULL) {
        errorLogPathname = server_root_relative(p, s->error_fname);
    }

    uid = (user_id == (uid_t) -1)  ? geteuid() : user_id;
#ifndef __EMX__
    gid = (group_id == (gid_t) -1) ? getegid() : group_id;
#else
    gid = (gid_t)-1;
#endif
    if((ptr=CreateDynamicDirAndMbox(uid, gid))!=NULL) {
        log_printf(s, "mod_fastcgi: %s\n", ptr);
    }

#if APACHE_RELEASE < 1030000
    spawn_child(p, (void *)FCGIProcMgrBoot, NULL, 
            kill_always, NULL, &fp);
#else
    spawn_child(p, FCGIProcMgrBoot, NULL, 
            kill_always, NULL, &fp);
#endif

    /* 
     * synchronization step, only needs to be performed once
     * since we employ the hack above to only get thus far on 
     * the second read of the configuration files.
     */
    do {
        memset(buf, 0, IOBUFSIZE);
        n = fread(buf, sizeof(char), IOBUFSIZE, fp);
    } while (n == -1 && ferror(fp) && errno == EINTR);
    if ((n == -1) || (n == 0)) {
        /* error has occurred */
        return;
    } else {
        procMgr = strtol(buf, NULL, 10);
        ASSERT(procMgr!=-1);
    }
    readingConfig = FALSE;
}

/*
 *----------------------------------------------------------------------
 *
 * Code related to the FastCGI request handler.
 *
 *----------------------------------------------------------------------
 */

/*
 *----------------------------------------------------------------------
 * 
 * SignalProcessManager --
 *
 *      Assembles a message to be sent to the process manager and
 *      puts it in the "mbox" file.  It then signals the process
 *      manager to process supplied information.
 *
 * Side effects:
 *      Mbox is appended.  Signal is sent to process manager.
 * 
 *----------------------------------------------------------------------
 */

void SignalProcessManager(char id, char *execPath, 
        unsigned long qsecs, unsigned long ctime, unsigned long now)
{
    AddNewRecord(id, execPath, qsecs, ctime, now);
    if(id!=REQ_COMPLETE) {
        kill(procMgr, SIGUSR2);
    }
}

/*
 *----------------------------------------------------------------------
 * 
 * SendPacketHeader --
 *
 *      Assembles and sends the FastCGI packet header for a given 
 *      request.  It is the caller's responsibility to make sure that
 *      there's enough space in the buffer, and that the data bytes
 *      (specified by 'len') are queued immediately following this
 *      header.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      Packet header queued.
 * 
 *----------------------------------------------------------------------
 */
#define MSB(x) ((x)/256)
#define LSB(x) ((x)%256)

static void SendPacketHeader(FastCgiInfo *infoPtr, int type, int len)
{
    FCGI_Header header;

    ASSERT(type > 0 && type <= FCGI_MAXTYPE);
    ASSERT(len >= 0 && len <= 0xffff);
    ASSERT(BufferFree(infoPtr->outbufPtr) > sizeof(FCGI_Header));

    /*
     * Assemble and queue the packet header.
     */
    header.version = FCGI_VERSION;
    header.type = type;
    header.requestIdB1 = (infoPtr->requestId >> 8) & 0xff;
    header.requestIdB0 = (infoPtr->requestId) & 0xff;
    header.contentLengthB1 = MSB(len);
    header.contentLengthB0 = LSB(len);
    header.paddingLength = 0;
    header.reserved = 0;
    BufferAddData(infoPtr->outbufPtr, (char *) &header, sizeof(FCGI_Header));
}

/*
 *----------------------------------------------------------------------
 *
 * MakeBeginRequestBody --
 *
 *      Constructs an FCGI_BeginRequestBody record.
 *
 *----------------------------------------------------------------------
 */

static void MakeBeginRequestBody(
        int role,
        int keepConnection,
        FCGI_BeginRequestBody *body)
{
    ASSERT((role >> 16) == 0);
    body->roleB1 = (role >>  8) & 0xff;
    body->roleB0 = (role      ) & 0xff;
    body->flags = (keepConnection) ? FCGI_KEEP_CONN : 0;
    memset(body->reserved, 0, sizeof(body->reserved));
}

/*
 *----------------------------------------------------------------------
 * 
 * SendBeginRequest - 
 *
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      Begin request queued.
 * 
 *----------------------------------------------------------------------
 */

static void SendBeginRequest(FastCgiInfo *infoPtr)
{
  FCGI_BeginRequestBody body;
  unsigned int bodySize;

  /*
   * We should be the first ones to use this buffer.
   */
  ASSERT(BufferLength(infoPtr->outbufPtr) == 0);

  bodySize = sizeof(FCGI_BeginRequestBody);
  /*
   * XXX: need infoPtr->keepConnection field, hard-coding FALSE below
   */
  MakeBeginRequestBody(FCGI_RESPONDER, FALSE, &body);
  SendPacketHeader(infoPtr, FCGI_BEGIN_REQUEST, bodySize);
  BufferAddData(infoPtr->outbufPtr, (char *) &body, bodySize);
}

/*
 *----------------------------------------------------------------------
 *
 * FCGIUtil_BuildNameValueHeader --
 *
 *      Builds a name-value pair header from the name length
 *      and the value length.  Stores the header into *headerBuffPtr,
 *      and stores the length of the header into *headerLenPtr.
 *
 * Side effects:
 *      Stores header's length (at most 8) into *headerLenPtr,
 *      and stores the header itself into
 *      headerBuffPtr[0 .. *headerLenPtr - 1].
 *
 *----------------------------------------------------------------------
 */

static void FCGIUtil_BuildNameValueHeader(
        int nameLen,
        int valueLen,
        unsigned char *headerBuffPtr,
        int *headerLenPtr) 
{
    unsigned char *startHeaderBuffPtr = headerBuffPtr;

    ASSERT(nameLen >= 0);
    if(nameLen < 0x80) {
        *headerBuffPtr++ = nameLen;
    } else {
        *headerBuffPtr++ = (nameLen >> 24) | 0x80;
        *headerBuffPtr++ = (nameLen >> 16);
        *headerBuffPtr++ = (nameLen >> 8);
        *headerBuffPtr++ = nameLen;
    }
    ASSERT(valueLen >= 0);
    if(valueLen < 0x80) {
        *headerBuffPtr++ = valueLen;
    } else {
        *headerBuffPtr++ = (valueLen >> 24) | 0x80;
        *headerBuffPtr++ = (valueLen >> 16);
        *headerBuffPtr++ = (valueLen >> 8);
        *headerBuffPtr++ = valueLen;
    }
    *headerLenPtr = headerBuffPtr - startHeaderBuffPtr;
}

/*
 *----------------------------------------------------------------------
 * 
 * SendEnvironment --
 *
 *      Queue the environment variables to a FastCGI server.  Assumes that
 *      there's enough space in the output buffer to hold the variables.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      Environment variables queued for delivery.
 * 
 *----------------------------------------------------------------------
 */

static void SendEnvironment(WS_Request *reqPtr, FastCgiInfo *infoPtr)
{
    int headerLen, nameLen, valueLen;
    char *equalPtr;
    unsigned char headerBuff[8];
    char **envp;

    /*
     * Send each environment item to the FastCGI server as a 
     * FastCGI format name-value pair.
     *
     * XXX: this code will break with the environment format used on NT.
     */

    add_common_vars(reqPtr);
    add_cgi_vars(reqPtr);
    envp = create_environment(reqPtr->pool, reqPtr->subprocess_env);
    for (; *envp ; envp++) {
        equalPtr = strchr(*envp, '=');
        ASSERT(equalPtr != NULL);
        nameLen = equalPtr - *envp;
        valueLen = strlen(equalPtr + 1);
        FCGIUtil_BuildNameValueHeader(
                nameLen,
                valueLen,
                &headerBuff[0],
                &headerLen);
        SendPacketHeader(
                infoPtr,
                FCGI_PARAMS,
                headerLen + nameLen + valueLen);
        BufferAddData(infoPtr->outbufPtr, (char *) &headerBuff[0], headerLen);
        BufferAddData(infoPtr->outbufPtr, *envp, nameLen);
        BufferAddData(infoPtr->outbufPtr, equalPtr + 1, valueLen);
    }
    SendPacketHeader(infoPtr, FCGI_PARAMS, 0);
}

/*
 *----------------------------------------------------------------------
 *   
 * ClientToCgiBuffer --
 *
 *      Move data from the client (buffer: reqInbuf) to the FastCGI
 *      application (buffer: outbuf).  This involves encapsulating
 *      the client data in FastCGI protocol records.
 *
 *      ClientToCgiBuffer has no preconditions.  When it returns,
 *      BufferFree(reqInbuf) > 0 || BufferFree(outbuf) < sizeof(FCGI_header)
 *             
 * Results:
 *      None.
 *
 * Side effects:
 *      Bytes moved from client input to FastCGI server output.
 *
 *----------------------------------------------------------------------
 */

static void ClientToCgiBuffer(FastCgiInfo *infoPtr)
{
    int movelen;
    int in_len, out_free;

    /*
     * If a previous call put an EOF indication in the output buffer,
     * nothing left to do.
     */
    if(infoPtr->eofSent) {
        return;
    }

    /*
     * If there's some client data and room for at least one byte
     * of data in the output buffer (after protocol overhead), then
     * move some data to the output buffer.
     */
    in_len = BufferLength(infoPtr->reqInbufPtr);
    out_free = max(0, BufferFree(infoPtr->outbufPtr) - sizeof(FCGI_Header));
    movelen = min(in_len, out_free);
    if(movelen > 0) {
        SendPacketHeader(infoPtr, FCGI_STDIN, movelen);
        BufferMove(infoPtr->outbufPtr, infoPtr->reqInbufPtr, movelen);
    }

    /*
     * If all the client data has been sent, and there's room
     * in the output buffer, indicate EOF.
     */
    if(movelen == in_len
            && infoPtr->expectingClientContent <= 0
            && BufferFree(infoPtr->outbufPtr) >= sizeof(FCGI_Header)) {
        SendPacketHeader(infoPtr, FCGI_STDIN, 0);
        infoPtr->eofSent = TRUE;
    }
}

/*
 *----------------------------------------------------------------------
 *   
 * CgiToClientBuffer --
 *
 *      Move data from FastCGI application (buffer: infoPtr->inbufPtr)
 *      to the client (buffer: infoPtr->header when parsing headers,
 *      infoPtr->reqOutbufPtr after parsing headers) or to the error log
 *      (buffer: infoPtr->errorOut).  This involves interpreting
 *      FastCGI protocol records.
 *             
 * Results:
 *      OK or SERVER_ERROR
 *
 * Side effects:
 *      Many.
 *
 *----------------------------------------------------------------------
 */

static int CgiToClientBuffer(FastCgiInfo *infoPtr)
{
    FCGI_Header header;
    int len;

    while(BufferLength(infoPtr->inbufPtr) > 0) {
        /*
         * State #1:  looking for the next complete packet header.
         */
        if(infoPtr->gotHeader == FALSE) {
            if(BufferLength(infoPtr->inbufPtr) < sizeof(FCGI_Header)) {
                return OK;
	    }
            BufferGetData(infoPtr->inbufPtr, (char *) &header, 
                    sizeof(FCGI_Header));
            /*
             * XXX: Better handling of packets with other version numbers
             * and other packet problems.
             */
            ASSERT(header.version == FCGI_VERSION);
            ASSERT(header.type <= FCGI_MAXTYPE);

            infoPtr->packetType = header.type;
            infoPtr->dataLen = (header.contentLengthB1 << 8)
                    + header.contentLengthB0; 
            infoPtr->gotHeader = TRUE;
            infoPtr->paddingLen = header.paddingLength;
        }

        /*
         * State #2:  got a header, and processing packet bytes.
         */
        len = min(infoPtr->dataLen, BufferLength(infoPtr->inbufPtr));
        ASSERT(len >= 0);
        switch(infoPtr->packetType) {
            case FCGI_STDOUT:
                if(len > 0) {
                    switch(infoPtr->parseHeader) {
                        case SCAN_CGI_READING_HEADERS:
                            BufferDStringAppend(infoPtr->header, 
                                    infoPtr->inbufPtr, len);
                            break;
                        case SCAN_CGI_FINISHED:
                            len = min(BufferFree(infoPtr->reqOutbufPtr), len);
                            if(len > 0) {
                                BufferMove(infoPtr->reqOutbufPtr,
                                        infoPtr->inbufPtr, len);
                            } else {
                                return OK;
                            }
                            break;
                        default:
                            /* Toss data on the floor */
                            break;
                    }
                    infoPtr->dataLen -= len;
                }
                break;
            case FCGI_STDERR:
                if(len > 0) {
                    BufferDStringAppend(infoPtr->errorOut,
                            infoPtr->inbufPtr, len);
                    infoPtr->dataLen -= len;
                }
                break;
            case FCGI_END_REQUEST:
                if(!infoPtr->readingEndRequestBody) {
                  if(infoPtr->dataLen != sizeof(FCGI_EndRequestBody)) {
                    sprintf(infoPtr->errorMsg,
                        "mod_fastcgi: FastCGI protocol error -"
                        " FCGI_END_REQUEST record body size %d !="
                        " sizeof(FCGI_EndRequestBody)", infoPtr->dataLen);
                    return SERVER_ERROR;
                  }
                  infoPtr->readingEndRequestBody = TRUE;
                }
                if(len>0) {
		    BufferMove(infoPtr->erBufPtr, infoPtr->inbufPtr, len);
		    infoPtr->dataLen -= len;                
		}
                if(infoPtr->dataLen == 0) {
                  FCGI_EndRequestBody *erBody = &infoPtr->endRequestBody;
                  BufferGetData(
                      infoPtr->erBufPtr, (char *) &infoPtr->endRequestBody, 
                      sizeof(FCGI_EndRequestBody));
                  if(erBody->protocolStatus != FCGI_REQUEST_COMPLETE) {
                    /*
                     * XXX: What to do with FCGI_OVERLOADED?
                     */
                    sprintf(infoPtr->errorMsg,
                        "mod_fastcgi: FastCGI protocol error -"
                        " FCGI_END_REQUEST record protocolStatus %d !="
                        " FCGI_REQUEST_COMPLETE", erBody->protocolStatus);
                    return SERVER_ERROR;
                  }
                  infoPtr->exitStatus = (erBody->appStatusB3 << 24)
                    + (erBody->appStatusB2 << 16)
                      + (erBody->appStatusB1 <<  8)
                        + (erBody->appStatusB0 );
                  infoPtr->exitStatusSet = TRUE;
                  infoPtr->readingEndRequestBody = FALSE;
                }
                break;
              case FCGI_GET_VALUES_RESULT:
                /* coming soon */
              case FCGI_UNKNOWN_TYPE:
                /* coming soon */

                /*
                 * Ignore unknown packet types from the FastCGI server.
                 */
            default:
                BufferToss(infoPtr->inbufPtr, len);
                infoPtr->dataLen -= len;            
                break;
        } /* switch */

        /*
         * Discard padding, then start looking for 
         * the next header.
         */
        if (infoPtr->dataLen == 0) {
            if (infoPtr->paddingLen > 0) {
                len = min(infoPtr->paddingLen,
                        BufferLength(infoPtr->inbufPtr));
                BufferToss(infoPtr->inbufPtr, len);
                infoPtr->paddingLen -= len;
            }
            if (infoPtr->paddingLen == 0) {
                infoPtr->gotHeader = FALSE;
	    }
        }
    } /* while */
    return OK;
}

/*
 *----------------------------------------------------------------------
 *
 * ScanLine --
 *
 *      Terminate a line:  scan to the next newline, scan back to the
 *      first non-space character and store a terminating zero.  Return
 *      the next character past the end of the newline.
 *
 *      If the end of the string is reached, return a pointer to the
 *      end of the string.
 *
 *      If the FIRST character(s) in the line are '\n' or "\r\n", the 
 *      first character is replaced with a NULL and next character
 *      past the newline is returned.  NOTE: this condition supercedes
 *      the processing of RFC-822 continuation lines.
 *
 *      If continuation is set to 'TRUE', then it parses a (possible)
 *      sequence of RFC-822 continuation lines.
 *
 * Results:
 *      As above.
 *
 * Side effects:
 *      Termination byte stored in string.
 *
 *----------------------------------------------------------------------
 */

char *ScanLine(char *start, int continuation)
{
    char *p = start;
    char *end = start;

    if(p[0] == '\r'  &&  p[1] == '\n') { /* If EOL in 1st 2 chars */
        p++;                              /*   point to \n and stop */
    } else if(*p != '\n') {
        if(continuation) {
            while(*p != '\0') {
                if(*p == '\n' && p[1] != ' ' && p[1] != '\t')
                    break;
                p++;
            }
        } else {
            while(*p != '\0' && *p != '\n') {
                p++;
            }
        }
    }

    end = p;
    if(*end != '\0') {
        end++;
    }

    /*
     * Trim any trailing whitespace.
     */
    while(isspace(p[-1]) && p > start) {
        p--;
    }

    *p = '\0';
    return end;
}

/*
 *----------------------------------------------------------------------
 *
 * ScanCGIHeader --
 *
 *      Call with reqPtr->parseHeader == SCAN_CGI_READING_HEADERS
 *      and initial script output in infoPtr->header.
 *
 *      If the initial script output does not include the header
 *      terminator ("\r\n\r\n") ScanCGIHeader returns with no side
 *      effects, to be called again when more script output
 *      has been appended to infoPtr->header.
 *
 *      If the initial script output includes the header terminator,
 *      ScanCGIHeader parses the headers and determines whether or
 *      not the remaining script output will be sent to the client.
 *      If so, ScanCGIHeader sends the HTTP response headers to the
 *      client and copies any non-header script output to the output
 *      buffer reqOutbuf.
 *
 * Results:
 *      none.
 *
 * Side effects:
 *      May set reqPtr->parseHeader to:
 *        SCAN_CGI_FINISHED -- headers parsed, returning script response
 *        SCAN_CGI_BAD_HEADER -- malformed header from script
 *                (specific message placed in infoPtr->errorMsg.)
 *        SCAN_CGI_INT_REDIRECT -- handler should perform internal redirect
 *        SCAN_CGI_SRV_REDIRECT -- handler should return REDIRECT
 *
 *----------------------------------------------------------------------
 */

void ScanCGIHeader(WS_Request *reqPtr, FastCgiInfo *infoPtr)
{
    char *p, *next, *name, *value, *location;
    int len, flag;
    int hasContentType, hasStatus, hasLocation;

    ASSERT(infoPtr->parseHeader == SCAN_CGI_READING_HEADERS);

    /*
     * Do we have the entire header?  Scan for the blank line that
     * terminates the header.
     */
    p = DStringValue(infoPtr->header);
    len = DStringLength(infoPtr->header);
    flag = 0;
    while(len-- && flag < 2) {
        switch(*p) {
            case '\r':  
                break;
            case '\n':
                flag++;
                break;
            default:
                flag = 0;
                break;
        }
        p++;
    }

    /*
     * Return (to be called later when we have more data)
     * if we don't have an entire header.
     */
    if(flag < 2) {
        return;
    }

    /*
     * Parse all the headers.
     */
    infoPtr->parseHeader = SCAN_CGI_FINISHED;
    hasContentType = hasStatus = hasLocation = FALSE;
    next = DStringValue(infoPtr->header);
    for(;;) {
        next = ScanLine(name = next, TRUE);
        if(*name == '\0') {
            break;
        }
        if((p = strchr(name, ':')) == NULL) {
            goto BadHeader;
        }
        value = p + 1;
        while(p != name && isspace(*(p - 1))) {
            p--;
        }
        if(p == name) {
            goto BadHeader;
        }
        *p = '\0';
        if(strpbrk(name, " \t") != NULL) {
            *p = ' ';
            goto BadHeader;
        }
        while(isspace(*value)) {
            value++;
        }

        /*
         * name is the trimmed header name and value the
         * trimmed header value.  Perform checks, then record value
         * in the request data structure.
         */
        if(!strcasecmp(name, "Content-type")) {
            if(hasContentType) {
                goto DuplicateNotAllowed;
            }
            hasContentType = TRUE;
            reqPtr->content_type = pstrdup(reqPtr->pool, value);
        } else if(!strcasecmp(name, "Status")) {
            int statusValue = strtol(value, NULL, 10);
            if(hasStatus) {
                goto DuplicateNotAllowed;
            } else if(statusValue < 0) {
                goto BadStatusValue;
            }
            hasStatus = TRUE;
            reqPtr->status = statusValue;
            reqPtr->status_line = pstrdup(reqPtr->pool, value);
        } else if(!strcasecmp(name, "Location")) {
            if(hasLocation) {
                goto DuplicateNotAllowed;
            }
            hasLocation = TRUE;
            table_set(reqPtr->headers_out, "Location", value);
        } else {
            /*
             * Don't merge headers.  If the script wants them
             * merged, the script can do the merging.
             */
            table_add(reqPtr->err_headers_out, name, value);
        }
    }
    /*
     * Who responds, this handler or Apache?
     */
    if(hasLocation) {
        location = table_get(reqPtr->headers_out, "Location");
        if(location[0] == '/') {
            /*
             * Location is an absolute path.  This handler will
             * consume all script output, then have Apache perform an
             * internal redirect.
             */
            infoPtr->parseHeader = SCAN_CGI_INT_REDIRECT;
            return;
        } else {
            /*
             * Location is an absolute URL.  If the script didn't
             * produce a Content-type header, this handler will
             * consume all script output and then have Apache generate
             * its standard redirect response.  Otherwise this handler
             * will transmit the script's response.
             */
            if(!hasContentType) {
                infoPtr->parseHeader = SCAN_CGI_SRV_REDIRECT;
                return;
            } else {
                reqPtr->status = REDIRECT;
		if (!hasStatus) {
		    reqPtr->status_line =
		        pstrdup(reqPtr->pool, "302 Moved Temporarily");
		}
            }
        }
    }
    /*
     * We're responding.  Send headers, buffer excess script output.
     */
    send_http_header(reqPtr);
    if(reqPtr->header_only) {
        return;
    }
    len = next - DStringValue(infoPtr->header);
    len = DStringLength(infoPtr->header) - len;
    ASSERT(len >= 0);
    if(BufferFree(infoPtr->reqOutbufPtr) < len) {
        /*
         * XXX: Since headers don't pass through reqOutbuf anymore,
         * the following code appears unnecessary.  But does Open Market
         * server have a lurking problem here?
         */
         int bufLen = BufferLength(infoPtr->reqOutbufPtr);
         Buffer *newBuf = BufferCreate(len + bufLen);
         BufferMove(newBuf, infoPtr->reqOutbufPtr, bufLen);
         BufferDelete(infoPtr->reqOutbufPtr);
         infoPtr->reqOutbufPtr = newBuf;
    }
    ASSERT(BufferFree(infoPtr->reqOutbufPtr) >= len);
    if(len > 0) {
        int sent = BufferAddData(infoPtr->reqOutbufPtr, next, len);
        ASSERT(sent == len);
    }
    return;

BadHeader:
    /*
     * Log an informative message, but only log first line of
     * a multi-line header
     */
    if((p = strpbrk(name, "\r\n")) != NULL) {
        *p = '\0';
    }
    Free(infoPtr->errorMsg);
    infoPtr->errorMsg = Malloc(FCGI_ERRMSG_LEN + strlen(name));
    sprintf(infoPtr->errorMsg,
            "mod_fastcgi: Malformed response header from app: '%s'", name);
    goto ErrorReturn;

DuplicateNotAllowed:
    sprintf(infoPtr->errorMsg,
            "mod_fastcgi: Duplicate CGI response header '%s'"
            " not allowed", name);
    goto ErrorReturn;

BadStatusValue:
    Free(infoPtr->errorMsg);
    infoPtr->errorMsg = Malloc(FCGI_ERRMSG_LEN + strlen(value));
    sprintf(infoPtr->errorMsg,
            "mod_fastcgi: Invalid Status value '%s'", value);
    goto ErrorReturn;

ErrorReturn:
    infoPtr->parseHeader = SCAN_CGI_BAD_HEADER;
    return;
}

/*
 *----------------------------------------------------------------------
 * 
 * FillOutbuf --
 *
 *      Reads data from the client and pushes it toward outbuf.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      When FillOutbuf returns, either
 *          both reqInbuf and outbuf are full
 *      or
 *          expectingClientContent <= 0 and either
 *          reqInbuf is empty or outbuf is full.
 *
 *      "outbuf full" means "at most sizeof(FCGI_Header) bytes free."
 *
 *      In case of an error reading from the client, sets
 *      expectingClientContent == -1.
 * 
 *----------------------------------------------------------------------
 */

static void FillOutbuf(WS_Request *reqPtr, FastCgiInfo *infoPtr)
{
    char *end;
    int count, countRead;
    while(BufferFree(infoPtr->reqInbufPtr) > 0
            || BufferFree(infoPtr->outbufPtr) > 0) {
        ClientToCgiBuffer(infoPtr);
        if(infoPtr->expectingClientContent <= 0) {
            break;
        }
        BufferPeekExpand(infoPtr->reqInbufPtr, &end, &count);
        if(count == 0) {
            break;
        }
        countRead = get_client_block(reqPtr, end, count);
        if(countRead > 0) {
            BufferExpand(infoPtr->reqInbufPtr, countRead);
        } else if (countRead == 0) {
            infoPtr->expectingClientContent = 0;
	} else {
            infoPtr->expectingClientContent = -1;
        }
    }
}

/*
 *----------------------------------------------------------------------
 * 
 * DrainReqOutbuf --
 *
 *      Writes some data to the client, if reqOutbuf contains any.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      When DrainReqOutbuf returns, BufferFree(reqOutbuf) > 0.
 *
 *      In case of an error writing to the client, reqOutbuf
 *      is drained anyway, with no error indication.
 * 
 *----------------------------------------------------------------------
 */

static void DrainReqOutbuf(WS_Request *reqPtr, FastCgiInfo *infoPtr)
{
    char *begin;
    int count;

    BufferPeekToss(infoPtr->reqOutbufPtr, &begin, &count);
    if(count == 0) {
        return;
    }
    if(!reqPtr->connection->aborted) {
        bwrite(reqPtr->connection->client, begin, count);
	bflush(reqPtr->connection->client);
    }
    BufferToss(infoPtr->reqOutbufPtr, count);
}

/*
 *----------------------------------------------------------------------
 * 
 * FastCgiDoWork --
 *
 *      This is the core routine for moving data between the FastCGI
 *      application and the Web server's client.
 *
 *      If the Web server's client closes the connection prematurely,
 *      FastCGIDoWork carries on until the FastCGI application is
 *      done with the request.  This avoids the FastCGI application
 *      receiving SIGPIPE.
 *
 *      If the FastCGI application sends a bad header, FastCGIDoWork
 *      continues reading from the application but sends no response
 *      to the client (returns SERVER_ERROR.)
 *
 *      If the FastCGI application requests an internal redirect,
 *      or requests a redirect response without returning content,
 *      FastCGIDoWork sends no response and returns OK; the variable
 *      infoPtr->parseHeader tells the story.
 *
 * Results:
 *      OK or SERVER_ERROR
 *
 * Side effects:
 *      many
 * 
 *----------------------------------------------------------------------
 */

static int FastCgiDoWork(WS_Request *reqPtr, FastCgiInfo *infoPtr)
{
    struct timeval timeOut, *timeOutPtr;
    fd_set read_set, write_set;
    int numFDs, status;
    int keepReadingFromFcgiApp, doClientWrite;
    char *fromStrerror;

    timeOut.tv_sec = 0;
    timeOut.tv_usec = 100000; /* 0.1 sec */
    FD_ZERO(&read_set);
    FD_ZERO(&write_set);
    numFDs = infoPtr->fd + 1;
    keepReadingFromFcgiApp = TRUE;
    while(keepReadingFromFcgiApp
            || BufferLength(infoPtr->inbufPtr) > 0
            || BufferLength(infoPtr->reqOutbufPtr) > 0) {
        if(!infoPtr->eofSent) {
            FillOutbuf(reqPtr, infoPtr);
	}

        /*
         * To avoid deadlock, don't do a blocking select to write to
         * the FastCGI application without selecting to read from the
         * FastCGI application.
         */
        doClientWrite = FALSE;
        if(keepReadingFromFcgiApp && BufferFree(infoPtr->inbufPtr) > 0) {
            FD_SET(infoPtr->fd, &read_set);
            if(BufferLength(infoPtr->outbufPtr) > 0) {
                FD_SET(infoPtr->fd, &write_set);
            } else {
                FD_CLR(infoPtr->fd, &write_set);
            }
            /*
             * If there's buffered data to send to the client, don't
             * wait indefinitely for the FastCGI app; the app might
             * be doing server push.
             */
            if(BufferLength(infoPtr->reqOutbufPtr) > 0) {
                timeOutPtr = &timeOut;
	    } else {
                timeOutPtr = NULL;
	    }
            /*
             * XXX: should always set a non-NULL timeout, to survive an
             * application that diverges.
             */
            status = select(
                    numFDs, &read_set, &write_set, NULL, timeOutPtr);
            if(status < 0) {
                goto AppIoError;
	    } else if(status == 0) {
                /*
                 * XXX: select timed out, so go ahead and write to client.
                 */
                doClientWrite = TRUE;
            }
            if(FD_ISSET(infoPtr->fd, &read_set)) {
                status = BufferRead(infoPtr->inbufPtr, infoPtr->fd);
                if(status < 0) {
                    goto AppIoError;
                } else if(status == 0) {
                    keepReadingFromFcgiApp = FALSE;
		}
            }
            if(FD_ISSET(infoPtr->fd, &write_set)) {
                if(BufferWrite(infoPtr->outbufPtr, infoPtr->fd) < 0) {
                    goto AppIoError;
		}
            }
        } else {
            doClientWrite = TRUE;
	}
        if(doClientWrite) {
            DrainReqOutbuf(reqPtr, infoPtr);
        }
        if(CgiToClientBuffer(infoPtr) != OK) {
            return SERVER_ERROR;
        }
        if(infoPtr->exitStatusSet) {
            keepReadingFromFcgiApp = FALSE;
        }
        if(infoPtr->parseHeader == SCAN_CGI_READING_HEADERS) {
            ScanCGIHeader(reqPtr, infoPtr);
        }
    } /* while */
    switch(infoPtr->parseHeader) {
        case SCAN_CGI_FINISHED:
            bflush(reqPtr->connection->client);
            bgetopt(reqPtr->connection->client,
                    BO_BYTECT, &reqPtr->bytes_sent);
            return OK;
        case SCAN_CGI_READING_HEADERS:
            goto UnterminatedHeader;
        case SCAN_CGI_BAD_HEADER:
            return SERVER_ERROR;
        case SCAN_CGI_INT_REDIRECT:
        case SCAN_CGI_SRV_REDIRECT:
            return OK;
        default:
            ASSERT(FALSE);
    }

UnterminatedHeader:
    sprintf(infoPtr->errorMsg,
            "mod_fastcgi: Unterminated CGI response headers,"
            " %d bytes received from app",
            DStringLength(infoPtr->header));
    return SERVER_ERROR;

AppIoError:
    /* No strerror prototype on SunOS? */
    fromStrerror = strerror(errno);
    Free(infoPtr->errorMsg);
    infoPtr->errorMsg = Malloc(FCGI_ERRMSG_LEN + strlen(fromStrerror));
    sprintf(infoPtr->errorMsg,
            "mod_fastcgi: OS error '%s' while communicating with app",
            fromStrerror);
    return SERVER_ERROR;
}

/*
 *----------------------------------------------------------------------
 * 
 * FcgiCleanUp --
 *
 *      Cleanup the resources 
 *
 * Results:
 *      none.
 *
 * Side effects:
 *      Free memory.
 * 
 *----------------------------------------------------------------------
 */

void FcgiCleanUp(FastCgiInfo *infoPtr)
{
    if(infoPtr == NULL) {
        return;
    }
    if(DStringLength(infoPtr->errorOut) > 0) {
        /*
         * Would like to call log_reason here, but log_reason
         * says "access failed" which isn't necessarily so.
         */
        fprintf(infoPtr->reqPtr->server->error_log,
                "[%s] mod_fastcgi: stderr output from %s: '%s'\n",
                get_time(), infoPtr->reqPtr->filename,
                DStringValue(infoPtr->errorOut));
        fflush(infoPtr->reqPtr->server->error_log);
    }
    BufferDelete(infoPtr->inbufPtr);
    BufferDelete(infoPtr->outbufPtr);
    BufferDelete(infoPtr->reqInbufPtr);
    BufferDelete(infoPtr->reqOutbufPtr);
    BufferDelete(infoPtr->erBufPtr);
    Free(infoPtr->errorMsg);
    DStringFree(infoPtr->header);
    DStringFree(infoPtr->errorOut);
    OS_Close(infoPtr->fd);
    Free( infoPtr->header );
    Free( infoPtr->errorOut );
    Free(infoPtr);
}

/*
 *----------------------------------------------------------------------
 * 
 * FastCgiHandler --
 *
 *      This routine gets called for a request that corresponds to
 *      a FastCGI connection.  It performs the request synchronously.
 *   
 * Results:
 *      Final status of request: OK or NOT_FOUND or SERVER_ERROR.
 *
 * Side effects:
 *      Request performed.
 * 
 *----------------------------------------------------------------------
 */

static int FastCgiHandler(WS_Request *reqPtr)
{
    FastCgiServerInfo *serverInfoPtr = NULL;
    FastCgiInfo *infoPtr = NULL;
    OS_IpcAddr *ipcAddrPtr = NULL;
    struct sockaddr_un* addrPtr = NULL;
    char *msg = NULL;
    char *argv0 = NULL;
    uid_t uid;
    gid_t gid;
    struct timeval start, ctime, qtime, tval;
    fd_set write_fds;
    int status, flags = 0;
    int dynamic = FALSE, result;
    int lockFd = 0;

    /* 
     * Model after mod_cgi::cgi_handler() to provide better 
     * compliance with HTTP 1.1 specification and security
     */
    no2slash(reqPtr->filename);
    if(reqPtr->method_number == M_OPTIONS) {
        /* do not allow anything but GET and POST */
        reqPtr->allowed |= (1<<M_GET);
	reqPtr->allowed |= (1<<M_POST);
	return DECLINED;
    }

    if((argv0 = strrchr(reqPtr->filename,'/')) != NULL) {
        argv0++;
    } else {
        argv0 = reqPtr->filename;
    }
    if(!(strncmp(argv0,"nph-",4))) {
        log_reason("NPH scripts are not allowed to run as FastCGI",
                reqPtr->filename, reqPtr);
	return FORBIDDEN;
    }

    if(!(allow_options(reqPtr) & OPT_EXECCGI)) {
        log_reason("Options ExecCGI is off in this directory", 
	        reqPtr->filename, reqPtr);
	return FORBIDDEN;
    }
    
    if((!strcmp(reqPtr->protocol, "INCLUDED")) && 
            ((allow_options(reqPtr) & OPT_INCNOEXEC))) {
        log_reason("Options IncludesNOEXEC is off in this directory",
                reqPtr->filename, reqPtr);
	return FORBIDDEN;
    }
    
    if (S_ISDIR(reqPtr->finfo.st_mode)) {
        log_reason("Attempt to invoke directory as FastCGI script",
	        reqPtr->filename, reqPtr);
	return FORBIDDEN;
    }

    if (reqPtr->finfo.st_mode == 0) {
        log_reason("Script is not found or unable to stat",
	        reqPtr->filename, reqPtr);
	return NOT_FOUND;
    }
    
    serverInfoPtr = LookupFcgiServerInfo(reqPtr->filename);
    if (serverInfoPtr == NULL) {
        /* 
         * Either this application does not exist, or it is 
	 * the invocation of the dynamic fastcgi 
	 * application.
	 */
        uid = (user_id == (uid_t) -1)  ? geteuid() : user_id;
#ifndef __EMX__
        gid = (group_id == (gid_t) -1) ? getegid() : group_id;
#else
	gid = (gid_t)-1;
#endif
        if(WS_Access(reqPtr->filename, &(reqPtr->finfo), X_OK, uid, gid)) {
            log_reason("mod_fastcgi: Requested application was not found",
                    reqPtr->filename, reqPtr);
            return NOT_FOUND;
	} else {
	    dynamic = TRUE;
	}
    }
 
    status = setup_client_block(reqPtr, REQUEST_CHUNKED_ERROR);
    if(status != OK) {
        return status;
    }

    /*
     * Allocate and initialize FastCGI private data to augment the request
     * structure.
     */
    infoPtr = (FastCgiInfo *) Malloc(sizeof(FastCgiInfo));
    infoPtr->serverPtr = serverInfoPtr;
    infoPtr->inbufPtr = BufferCreate(SERVER_BUFSIZE);
    infoPtr->outbufPtr = BufferCreate(SERVER_BUFSIZE);
    infoPtr->gotHeader = FALSE;
    infoPtr->reqInbufPtr = BufferCreate(SERVER_BUFSIZE);
    infoPtr->reqOutbufPtr = BufferCreate(SERVER_BUFSIZE);
    infoPtr->errorMsg =  Malloc(FCGI_ERRMSG_LEN);
    infoPtr->parseHeader = SCAN_CGI_READING_HEADERS;
    infoPtr->header = (DString *) malloc(sizeof(DString));
    infoPtr->errorOut = (DString *) malloc(sizeof(DString));
    infoPtr->reqPtr = reqPtr;
    DStringInit(infoPtr->header);
    DStringInit(infoPtr->errorOut);
    infoPtr->erBufPtr = BufferCreate(sizeof(FCGI_EndRequestBody) + 1);
    infoPtr->readingEndRequestBody = FALSE;
    infoPtr->exitStatus = 0;
    infoPtr->exitStatusSet = FALSE;
    infoPtr->requestId = 1; /* anything but zero is OK here */
    infoPtr->eofSent = FALSE;
    infoPtr->fd = -1;
    infoPtr->expectingClientContent = (should_client_block(reqPtr) != 0);

    SendBeginRequest(infoPtr);
    SendEnvironment(reqPtr, infoPtr);

    /*
     * Read as much as possible from the client now, before connecting
     * to the FastCGI application.
     */
    soft_timeout("read script input or send script output", reqPtr);
    FillOutbuf(reqPtr, infoPtr);

    /*
     * Open a connection to the FastCGI application.
     */
    if(dynamic==TRUE) {
        char *lockFileName = MakeLockFileName(reqPtr->filename);
	do {
	    result = DoesLockExist(lockFileName);
	    switch (result) {
	        case -1:
	            sprintf(infoPtr->errorMsg,
                    "mod_fastcgi: Error in DoesLockExist()");
	            goto ErrorReturn;
	        case 0:
		    SignalProcessManager(PLEASE_START, 
		            reqPtr->filename, 0, 0, 0);
		    sleep(1);
                    break;
	        case 1:
		    if (autoUpdate) {
		      /* there's a process running. See if the binary is newer,
		       * meaning we need to restart the process.
		       */
		      struct stat lstbuf, bstbuf;
		      if (stat(lockFileName, &lstbuf)>=0 &&
			  stat(reqPtr->filename, &bstbuf) >=0 &&
			  lstbuf.st_mtime < bstbuf.st_mtime) {
			/* ask the process manager to start it.
			 * it will notice that the binary is newer,
			 * and do a restart instead.
			 */
			SignalProcessManager(PLEASE_START, 
					     reqPtr->filename, 0, 0, 0);
			sleep(1);
			break;
		      }
		    }
   	    	    lockFd = open(lockFileName,O_APPEND);
		    result = (lockFd<0)?(0):(1);
		    break;
	    }
	} while (result!=1);
	if(ReadwLock(lockFd)<0) {
	    sprintf(infoPtr->errorMsg,
                    "mod_fastcgi: Can't obtain a read lock");
	    goto ErrorReturn;
	}
	free(lockFileName);
    }

    /* create connection point */
    if(dynamic==TRUE) {
        ipcAddrPtr = (OS_IpcAddr *) OS_InitIpcAddr();
	/* need to fill in the serverAddr structure, even 
	   though the process manager is the one actually
	   responsible for creating a socket */
	addrPtr = (struct sockaddr_un *) Malloc(sizeof(struct sockaddr_un));
	ipcAddrPtr->serverAddr = (struct sockaddr *) addrPtr;
	if(OS_BuildSockAddrUn(MakeSocketName(reqPtr->filename, 
		NULL, -1, &ipcAddrPtr->bindPath, 1),
                addrPtr, &ipcAddrPtr->addrLen)) {
            goto ConnectionErrorReturn;
        }  
	ipcAddrPtr->addrType = TYPE_LOCAL;
    } else {
        ASSERT(serverInfoPtr != NULL);
        ipcAddrPtr = (OS_IpcAddr *) serverInfoPtr->ipcAddr;
    }
    if((infoPtr->fd = OS_Socket(ipcAddrPtr->serverAddr->sa_family, 
            SOCK_STREAM, 0)) < 0) {
        goto ConnectionErrorReturn;
    }

    /* connect */
    if(dynamic==TRUE) {
        if((flags=fcntl(infoPtr->fd, F_GETFL, 0))<0) {
	    sprintf(infoPtr->errorMsg,
                    "mod_fastcgi: Unable to get/set descriptor flags");
            goto ErrorReturn;
        }
	if((fcntl(infoPtr->fd, F_SETFL, (flags|O_NONBLOCK|O_NDELAY)))<0) {
	    sprintf(infoPtr->errorMsg,
                    "mod_fastcgi: Unable to get/set descriptor flags");
            goto ErrorReturn;
	} 
	if(gettimeofday(&start,NULL)<0) {
	    sprintf(infoPtr->errorMsg,
                    "mod_fastcgi: Unable to get the time of day");
            goto ErrorReturn;
	}
        FD_ZERO(&write_fds);
	tval.tv_sec = startProcessDelay;
	tval.tv_usec = 0;
	if(connect(infoPtr->fd, (struct sockaddr *)ipcAddrPtr->serverAddr, 
		ipcAddrPtr->addrLen)<0) {
	    if(errno!=EINPROGRESS) {
	        goto ConnectionErrorReturn;
	    } else {
	        do {
		    FD_SET(infoPtr->fd, &write_fds);
		    status=select((infoPtr->fd+1), NULL, &write_fds, 
		            NULL, &tval);
		    if(status<0) {
		        goto ConnectionErrorReturn;
		    } else {
		        if(gettimeofday(&qtime,NULL)<0) {
		            sprintf(infoPtr->errorMsg,
                                "mod_fastcgi: Unable to get the time of day");
			    goto ErrorReturn;
			}
			if(status==0) {
			    SignalProcessManager(CONN_TIMEOUT, 
		                  reqPtr->filename,
				  (unsigned long)startProcessDelay*1000000,
			          0, 0);
			} else {
			    break;
			}
		    }
		} while((qtime.tv_sec-start.tv_sec)<appConnTimeout);
		if((qtime.tv_sec-start.tv_sec)>=appConnTimeout) {
		    status = SERVER_ERROR;
		    Unlock(lockFd);
		    close(lockFd);
		    goto CleanupReturn;
		}
	    }
	} else {
	  if(gettimeofday(&qtime,NULL)<0) {
	    sprintf(infoPtr->errorMsg,
		    "mod_fastcgi: Unable to get the time of day");
	    goto ErrorReturn;
	  }
	}
    } else {
        if(connect(infoPtr->fd, (struct sockaddr *) ipcAddrPtr->serverAddr,
                ipcAddrPtr->addrLen) < 0) {
            goto ConnectionErrorReturn;
        }
    }

    if(dynamic==TRUE) {
        if((fcntl(infoPtr->fd, F_SETFL, flags))<0) {
            sprintf(infoPtr->errorMsg,
                    "mod_fastcgi: Unable to get/set descriptor flags");
	    goto ErrorReturn;
	}
    } 

    /* communicate with fcgi app */
    status = FastCgiDoWork(reqPtr, infoPtr);
    kill_timeout(reqPtr);

    if(dynamic==TRUE) {
        if(gettimeofday(&ctime, NULL)<0) {
	    sprintf(infoPtr->errorMsg,
                    "mod_fastcgi: Unable to get the time of day");
            goto ErrorReturn;
	}
	SignalProcessManager(REQ_COMPLETE, 
	        reqPtr->filename,
                (unsigned long)((qtime.tv_sec-start.tv_sec)*1000000
                    +(qtime.tv_usec-start.tv_usec)), 
		(unsigned long)((ctime.tv_sec-qtime.tv_sec)*1000000
                    +(ctime.tv_usec-qtime.tv_usec)), 
                (unsigned long)ctime.tv_sec);
    }

    if(status != OK) {
        goto ErrorReturn;
    };
    switch(infoPtr->parseHeader) {
        case SCAN_CGI_INT_REDIRECT:
            /* 
	     * Since the message of the body has already 
	     * been read, don't allow the redirected request
	     * to think it has one.
	     */
            table_unset(reqPtr->headers_in, "Content-length");
            internal_redirect_handler(
                    table_get(reqPtr->headers_out, "Location"), reqPtr);
            break;
        case SCAN_CGI_SRV_REDIRECT:
            status = REDIRECT;
            break;
    }
    if (dynamic==TRUE) {
        Unlock(lockFd);
        close(lockFd);
    }
    goto CleanupReturn;

ConnectionErrorReturn:
    msg = (char *) strerror(errno);
    if (msg == NULL) {
        msg = "errno out of range";
    }
    Free(infoPtr->errorMsg);
    if (dynamic==TRUE) {
        OS_FreeIpcAddr(ipcAddrPtr);
    }
    infoPtr->errorMsg = Malloc(FCGI_ERRMSG_LEN + strlen(msg));
    sprintf(infoPtr->errorMsg,
            "mod_fastcgi: Could not connect to application,"
            " OS error '%s'", msg);
ErrorReturn:
    log_reason(infoPtr->errorMsg, reqPtr->filename, reqPtr);
    FcgiCleanUp(infoPtr);
    if(dynamic==TRUE) {
        OS_FreeIpcAddr(ipcAddrPtr);
        Unlock(lockFd);
        close(lockFd);
    }
    return SERVER_ERROR;

CleanupReturn:
    FcgiCleanUp(infoPtr);
    return status;
}


command_rec fastcgi_cmds[] = {
{ "AppClass", AppClassCmd, NULL, RSRC_CONF, RAW_ARGS, 
    NULL },
{ "ExternalAppClass", ExternalAppClassCmd, NULL, RSRC_CONF, RAW_ARGS, 
    NULL },
{ "FastCgiIpcDir", FastCgiIpcDirCmd, NULL, RSRC_CONF, TAKE1,
    NULL },
{ "FCGIConfig", FCGIConfigCmd, NULL, RSRC_CONF, RAW_ARGS, 
    NULL },
{ NULL }
};


handler_rec fastcgi_handlers[] = {
{ FCGI_MAGIC_TYPE, FastCgiHandler },
{ "fastcgi-script", FastCgiHandler },
{ NULL }
};


module fastcgi_module = {
   STANDARD_MODULE_STUFF,
   ModFastCgiInit,              /* initializer */
   NULL,                        /* dir config creater */
   NULL,                        /* dir merger --- default is to override */
   NULL,                        /* server config */
   NULL,                        /* merge server config */
   fastcgi_cmds,                /* command table */
   fastcgi_handlers,            /* handlers */
   NULL,                        /* filename translation */
   NULL,                        /* check_user_id */
   NULL,                        /* check auth */
   NULL,                        /* check access */
   NULL,                        /* type_checker */
   NULL,                        /* fixups */
   NULL,                        /* logger */
   NULL                         /* header-parser */
};
