/*
 * mod_fastcgi.c --
 *
 *      Apache server module for FastCGI.
 *
 *  $Id: mod_fastcgi.c,v 1.56 1998/11/24 04:46:31 roberts Exp $
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
 *
 *  Patches for suexec handling by
 *  Brian Grossman <brian@SoftHome.net> and
 *  Rob Saccoccio <robs@ipass.net>
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
#if APACHE_RELEASE >= 1030000
#if MODULE_MAGIC_NUMBER >= 19980713
#include "ap_compat.h"
#include "ap_config.h"
#else
#include "compat.h"
#endif
#endif
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
#include "fcgibuf.h"

#define	FCGI_LOG_EMERG    __FILE__,__LINE__,APLOG_EMERG		/* system is unusable */
#define	FCGI_LOG_ALERT    __FILE__,__LINE__,APLOG_ALERT		/* action must be taken immediately */
#define	FCGI_LOG_CRIT     __FILE__,__LINE__,APLOG_CRIT		/* critical conditions */
#define	FCGI_LOG_ERR      __FILE__,__LINE__,APLOG_ERR		/* error conditions */
#define	FCGI_LOG_WARNING  __FILE__,__LINE__,APLOG_WARNING	/* warning conditions */
#define	FCGI_LOG_NOTICE   __FILE__,__LINE__,APLOG_NOTICE	/* normal but significant condition */
#define	FCGI_LOG_INFO     __FILE__,__LINE__,APLOG_INFO		/* informational */
#define	FCGI_LOG_DEBUG    __FILE__,__LINE__,APLOG_DEBUG		/* debug-level messages */

static FILE* errorLog = (FILE *)-1;


/*******************************************************************************
 * Build a Domain Socket Address structure, and calculate its size.
 * The error message is allocated from the pool p. If you don't want the
 * struct sockaddr_un also allocated from p, pass it preallocated (!=NULL).
 */
static const char *sock_makeDomainAddr(pool *p, struct sockaddr_un **sockAddr,
        int *sockAddrLen, const char *sockPath)
{
    int sockPathLen = strlen(sockPath);

    if (sockPathLen >= sizeof((*sockAddr)->sun_path)) {
        return pstrcat(p, "path \"", sockPath,
                       "\" is too long for a Domain socket", NULL);
    }

    if (*sockAddr == NULL)
        *sockAddr = pcalloc(p, sizeof(struct sockaddr_un));
    else
        memset(*sockAddr, 0, sizeof(struct sockaddr_un));

    (*sockAddr)->sun_family = AF_UNIX;
    strcpy((*sockAddr)->sun_path, sockPath);

#ifndef SUN_LEN
#define SUN_LEN(sock) \
    (sizeof(*(sock)) - sizeof((sock)->sun_path) + strlen((sock)->sun_path))
#endif
    *sockAddrLen = SUN_LEN(*sockAddr);
    return NULL;
}

/*******************************************************************************
 * Bind an address to a socket and set it to listen for incoming connects.
 * The error messages are allocated from the pool p, use temp storage.
 * Don't forget to close the socket, if an error occurs.
 */
const char *sock_bindAndListen(pool *p, struct sockaddr *sockAddr,
                           int sockAddrLen, int backlog, int sock)
{
    if (sockAddr->sa_family == AF_UNIX) {
        /* Remove any existing socket file.. just in case */
        unlink(((struct sockaddr_un *)sockAddr)->sun_path);
    } else {
        int flag = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag));
    }

    /* Bind it to the sockAddr */
    if (bind(sock, sockAddr, sockAddrLen))
        return pstrcat(p, "bind() failed: ", strerror(errno), NULL);

    /* Twiddle ownership and permissions */
    if (sockAddr->sa_family == AF_UNIX) {
#ifndef __EMX__
        /* If we're root, we're gonna setuid/setgid, so we need to chown */
        if (geteuid() == 0 &&
            chown(((struct sockaddr_un *)sockAddr)->sun_path, user_id, group_id))
            return pstrcat(p, "chown() of socket failed: ", strerror(errno), NULL);
#endif
        if (chmod(((struct sockaddr_un *)sockAddr)->sun_path,
                S_IRUSR | S_IWUSR))
            return pstrcat(p, "chmod() of socket failed: ", strerror(errno), NULL);
    }

    /* Set to listen */
    if (listen(sock, backlog))
        return pstrcat(p, "listen() failed: ", strerror(errno), NULL);

    return NULL;
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

int ResolveHostname(const char *hostname, struct in_addr *addr)
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

/*******************************************************************************
 * Build an Inet Socket Address structure, and calculate its size.
 * The error message is allocated from the pool p. If you don't want the
 * struct sockaddr_in also allocated from p, pass it preallocated (!=NULL).
 */
static const char *sock_makeInetAddr(pool *p, struct sockaddr_in **sockAddr,
        int *sockAddrLen, const char *host, int port)
{
    if (*sockAddr == NULL)
        *sockAddr = pcalloc(p, sizeof(struct sockaddr_in));
    else
        memset(*sockAddr, 0, sizeof(struct sockaddr_in));

    (*sockAddr)->sin_family = AF_INET;
    (*sockAddr)->sin_port = htons(port);

    /* Get an in_addr represention of the host */
    if (host != NULL) {
        if (ResolveHostname(host, &(*sockAddr)->sin_addr) != 1) {
            return pstrcat(p, "failed to resolve \"", host,
                           "\" to exactly one IP address", NULL);
        }
    } else {
      (*sockAddr)->sin_addr.s_addr = htonl(INADDR_ANY);
    }

    *sockAddrLen = sizeof(struct sockaddr_in);
    return NULL;
}


/*
 *----------------------------------------------------------------------
 *
 * WS_Access --
 *
 *    Determine if a user with the specified user and group id
 *    will be able to access the specified file.  This routine depends
 *    on being called with enough permission to stat the file
 *    (e.g. root).
 *
 *    'mode' is the bitwise or of R_OK, W_OK, or X_OK.
 *
 *    This call is similar to the POSIX access() call, with extra
 *    options for specifying the user and group ID to use for
 *    checking.
 *
 * Results:
 *      -1 if no access or error accessing, 0 otherwise.
 *
 * Side effects:
 *    None.
 *
 *----------------------------------------------------------------------
 */
#define WS_SET_errno(x) errno = x

/* @@@ This should return const char * w/ info about the failure */
int WS_Access(const char *path, struct stat *statBuf,
        int mode, uid_t uid, gid_t gid)
{
    char **names;
    struct group *grp;
    struct passwd *usr;
    static struct stat staticStatBuf;

    if (statBuf==NULL) {
        statBuf = &staticStatBuf;
        if (stat(path, statBuf) < 0) {
            return -1;
        }
    }
    /*
     * If the uid owns the file, check the owner bits.
     */
    if(uid == statBuf->st_uid) {
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
     * If the gid is same as the file's group, check the group bits.
     */
    if(gid == statBuf->st_gid) {
        if((mode & R_OK) && !(statBuf->st_mode & S_IRGRP))
            goto no_access;

        if((mode & W_OK) && !(statBuf->st_mode & S_IWGRP))
            goto no_access;

        if((mode & X_OK) && !(statBuf->st_mode & S_IXGRP))
            goto no_access;

        return 0;
    }

    /*
     * Get the user membership for the file's group.  If the
     * uid is a member, check the group bits.
     */
    grp = getgrgid(statBuf->st_gid);
    usr = getpwuid(uid);
    if (grp && usr) {
        for (names = grp->gr_mem; *names != NULL; names++) {
            if (!strcmp(*names, usr->pw_name)) {
                if ((mode & R_OK) && !(statBuf->st_mode & S_IRGRP)) {
                    goto no_access;
                }
                if ((mode & W_OK) && !(statBuf->st_mode & S_IWGRP)) {
                    goto no_access;
                }
                if ((mode & X_OK) && !(statBuf->st_mode & S_IXGRP)) {
                    goto no_access;
                }
                return 0;
            }
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
#define FCGI_MAGIC_TYPE "application/x-httpd-fcgi"
#define FCGI_DEFAULT_LISTEN_Q 5            /* listen queue size */
#define FCGI_DEFAULT_RESTART_DELAY 5       /* delay between restarts */
#define DEFAULT_INIT_START_DELAY 1         /* delay between starts */
#define FCGI_DEFAULT_PRIORITY 0            /* process priority - not used */
#define FCGI_ERRMSG_LEN 200                /* size of error buffer */
#define FCGI_MIN_EXEC_RETRY_DELAY 10       /* minimum number of seconds to
                                              wait before restarting */
#define MAX_INIT_ENV_VARS 64               /* max # of -initial-env options */

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
                                            * (1-dynamicGain), so making it
                                            * smaller weights them more heavily
                                            * compared to the current value,
                                            * which is scaled by dynamicGain */
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
                                            * processes exceeds dynamicMaxProcs, then
                                            * the KillDynamicProcs() is invoked */
#define FCGI_DEFAULT_RESTART_DYNAMIC 0     /* Do not restart dynamic processes */
#define FCGI_DEFAULT_AUTOUPDATE 0          /* do not automatically restart
                                            * fcgi apps when the binary on the
                                            * disk is changed. */

#define DEFAULT_SOCK_DIR "/tmp/fcgi"       /* Default dir for Unix/Domain sockets */

/*
 * ServerProcess holds data for each process associated with
 * a class.  It is embedded in FastCgiServerInfo below.
 */
typedef struct _FcgiProcessInfo {
    pid_t pid;                       /* pid of associated process */
    enum {STATE_STARTED,             /* currently running */
          STATE_NEEDS_STARTING,      /* needs to be started by PM */
          STATE_VICTIM,              /* SIGTERM was sent by PM */
          STATE_KILLED,              /* a wait() collected VICTIM */
          STATE_READY}               /* empty cell, init state */
          state;                     /* state of the process */
} ServerProcess;

/*
 * FastCgiServerInfo holds info for each AppClass specified in this
 * Web server's configuration.
 */
typedef struct _FastCgiServerInfo {
    const char *execPath;           /* pathname of executable */
    const char * const *envp;       /* if NOT NULL, this is the env to send
                                     * to the fcgi app when starting a server
                                     * managed app. */
    u_int listenQueueDepth;         /* size of listen queue for IPC */
    u_int appConnectTimeout;        /* timeout (sec) for connect() requests */
    u_int numProcesses;             /* max allowed processes of this class,
                                     * or for dynamic apps, the number of
                                     * processes actually running */
    time_t restartTime;             /* most recent time when the process
                                     * manager started a process in this
                                     * class. */
    u_int initStartDelay;           /* min number of seconds to wait between
                                     * starting of AppClass processes at init */
    u_int restartDelay;             /* number of seconds to wait between
                                     * restarts after failure.  Can be zero. */
    int restartOnExit;              /* = TRUE = restart. else terminate/free */
    u_int numRestarts;              /* Total number of restarts */
    u_int numFailures;              /* num restarts due to exit failure */
    struct sockaddr *sockAddr;      /* Socket Address of FCGI app server class */
    int sockAddrLen;                /* Length of socket */
    enum {APP_CLASS_UNKNOWN,
          APP_CLASS_STANDARD,
          APP_CLASS_EXTERNAL,
          APP_CLASS_DYNAMIC}
         directive;                 /* AppClass or ExternalAppClass */
    const char *sockPath;           /* Name used to create a socket */
    const char *host;               /* Hostname for externally managed
                                     * FastCGI application processes */
    u_int port;                     /* Port number either for externally
                                     * managed FastCGI applications or for
                                     * server managed FastCGI applications,
                                     * where server became application mngr. */
    int listenFd;                   /* Listener socket of FCGI app server
                                     * class.  Passed to app server process
                                     * at process creation. */
    u_int processPriority;          /* If locally server managed process,
                                     * this is the priority to run the
                                     * processes in this class at. */
    struct _FcgiProcessInfo *procs; /* Pointer to array of
                                     * processes belonging to this class. */
    int keepConnection;             /* = 1 = maintain connection to app. */
    uid_t uid;                      /* uid this app should run as (suexec) */
    gid_t gid;                      /* gid this app should run as (suexec) */
    const char *username;           /* suexec user arg */
    const char *group;              /* suexec group arg, AND used in comm
                                     * between RH and PM */
    const char *user;               /* used in comm between RH and PM */
    /* Dynamic FastCGI apps configuration parameters */
    u_long totalConnTime;           /* microseconds spent by the web server
                                     * waiting while fastcgi app performs
                                     * request processing since the last
                                     * dynamicUpdateInterval */
    u_long smoothConnTime;          /* exponentially decayed values of the
                                     * connection times. */
    u_long totalQueueTime;          /* microseconds spent by the web server
                                     * waiting to connect to the fastcgi app
                                     * since the last dynamicUpdateInterval. */
    struct _FastCgiServerInfo *next;
} FastCgiServerInfo;


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
    Buffer *inbufPtr;               /* input buffer from FastCgi appliation */
    Buffer *outbufPtr;              /* output buffer to FastCgi application */
    Buffer *reqInbufPtr;            /* client input buffer */
    Buffer *reqOutbufPtr;           /* client output buffer */
    char *errorMsg;                 /* error message from failed request */
    int expectingClientContent;     /* >0 => more content, <=0 => no more */
    char *header;
    char *errorOut;
    int parseHeader;                /* TRUE iff parsing response headers */
    request_rec *reqPtr;
    int readingEndRequestBody;
    FCGI_EndRequestBody endRequestBody;
    Buffer *erBufPtr;
    int exitStatus;
    int exitStatusSet;
    int requestId;
    int eofSent;
    int dynamic;                    /* whether or not this is a dynamic app */
    struct timeval startTime;       /* dynamic app's connect() attempt start time */
    struct timeval queueTime;       /* dynamic app's connect() complete time */
    struct timeval completeTime;    /* dynamic app's connection close() time */
    int lockFd;                     /* dynamic app's lockfile file descriptor */
    int keepReadingFromFcgiApp;     /* still more to read from fcgi app? */
    const char *user;               /* user used to invoke app (suexec) */
    const char *group;              /* group used to invoke app (suexec) */
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
static pool *fcgiPool;                           /* the config pool */
static uid_t fcgi_user_id;                       /* the run uid of Apache & PM */
static gid_t fcgi_group_id;                      /* the run gid of Apache & PM */

static FastCgiServerInfo *fastCgiServers = NULL; /* AppClasses */
static const char *fcgi_suexec = NULL;           /* suexec_bin path */
static char *ipcDir = DEFAULT_SOCK_DIR;          /* default FastCgiIpcDir */
static char *ipcDynamicDir = NULL;               /* directory for the dynamic
                                                  * fastcgi apps' sockets */
static int globalNumInstances = 0;               /* number of running apps */
static time_t epoch = 0;                         /* last time kill_procs was
                                                  * invoked by process mgr */
static time_t lastAnalyze = 0;                   /* last time calculation was
                                                  * made for the dynamic procs*/
static char *mbox = NULL;                        /* file through which the fcgi
                                                  * procs communicate with WS */

static u_int dynamicMaxProcs = FCGI_DEFAULT_MAX_PROCS;
static u_int dynamicMinProcs = FCGI_DEFAULT_MIN_PROCS;
static u_int dynamicMaxClassProcs = FCGI_DEFAULT_MAX_CLASS_PROCS;
static u_int dynamicKillInterval = FCGI_DEFAULT_KILL_INTERVAL;
static u_int dynamicUpdateInterval = FCGI_DEFAULT_UPDATE_INTERVAL;
static float dynamicGain = FCGI_DEFAULT_GAIN;
static u_int dynamicThreshhold1 = FCGI_DEFAULT_THRESHHOLD_1;
static u_int dynamicThreshholdN = FCGI_DEFAULT_THRESHHOLD_N;
static u_int dynamicPleaseStartDelay = FCGI_DEFAULT_START_PROCESS_DELAY;
static u_int dynamicAppConnectTimeout = FCGI_DEFAULT_APP_CONN_TIMEOUT;
static const char * const *dynamicEnvp = NULL;
static u_int dynamicProcessSlack = FCGI_DEFAULT_PROCESS_SLACK;
static int dynamicAutoRestart = FCGI_DEFAULT_RESTART_DYNAMIC;
static int dynamicAutoUpdate = FCGI_DEFAULT_AUTOUPDATE;
static u_int dynamicListenQueueDepth = FCGI_DEFAULT_LISTEN_Q;
static u_int dynamicInitStartDelay = DEFAULT_INIT_START_DELAY;
static u_int dynamicRestartDelay = FCGI_DEFAULT_RESTART_DELAY;



/*******************************************************************************
 * Compute printable MD5 hash. Pool p is used for scratch as well as for
 * allocating the hash - use temp storage, and dup it if you need to keep it.
 */
static char *sock_makeHash(pool *p, const char *path,
                         const char *user, const char *group)
{
    char *buf = pstrcat(p, path, user, group, NULL);

    /* Canonicalize the path (remove "//", ".", "..") */
    getparents(buf);

    return ap_md5(p, (unsigned char *)buf);
}

/*******************************************************************************
 * Return absolute path to file in either "regular" FCGI socket directory or
 * the dynamic directory.  Result is allocated in pool p.
 */
static const char *sock_makePath(pool *p, const char *file, int dynamic)
{
    return (const char *)pstrcat(p, dynamic ? ipcDynamicDir : ipcDir,
                                 "/", file, NULL);
}

/*******************************************************************************
 * Allocate a new string from pool p with the name of a Unix/Domain socket's
 * lock file (used by dynamic only).
 */
const char *dynamic_makeLockPath(pool *p, const char *sockPath)
{
    return pstrcat(p, sockPath, ".lock", NULL);
}

/*******************************************************************************
 * Find a FastCGI server with a matching execPath, and if fcgi_suexec is
 * enabled with matching uid and gid.
 */
FastCgiServerInfo *server_getById(const char *ePath, uid_t uid, gid_t gid)
{
    FastCgiServerInfo *s;

    for (s = fastCgiServers; s != NULL; s = s->next) {
        if (strcmp(s->execPath, ePath) == 0) {
            if (fcgi_suexec == NULL || (uid == s->uid && gid == s->gid))
                return s;
        }
    }
    return NULL;
}

/*******************************************************************************
 * Find a FastCGI server with a matching execPath, and if fcgi_suexec is
 * enabled with matching user and group.
 */
FastCgiServerInfo *server_get(const char *ePath, const char *user, const char *group)
{
    FastCgiServerInfo *s;

    for (s = fastCgiServers; s != NULL; s = s->next) {
        if (strcmp(s->execPath, ePath) == 0) {
            if (fcgi_suexec == NULL)
                return s;

            if (strcmp(user, s->user) == 0
                && (user[0] == '~' || strcmp(group, s->group) == 0))
                return s;
        }
    }
    return NULL;
}


/*******************************************************************************
 * Allocate a new FastCGI server record from pool p with default values.
 */
static FastCgiServerInfo *server_new(pool *p)
{
    FastCgiServerInfo *s =
        (FastCgiServerInfo *) pcalloc(p, sizeof(FastCgiServerInfo));

    /* Initialize anything who's init state is not zeroizzzzed */
    s->listenQueueDepth = FCGI_DEFAULT_LISTEN_Q;
    s->appConnectTimeout = FCGI_DEFAULT_APP_CONN_TIMEOUT;
    s->initStartDelay = DEFAULT_INIT_START_DELAY;
    s->restartDelay = FCGI_DEFAULT_RESTART_DELAY;
    s->restartOnExit = FALSE;
    s->directive = APP_CLASS_UNKNOWN;
    s->processPriority = FCGI_DEFAULT_PRIORITY;
    s->listenFd = -2;

    return s;
}

/*******************************************************************************
 * Add the server to the linked list of FastCGI servers.
 */
static void server_add(FastCgiServerInfo *s)
{
    s->next = fastCgiServers;
    fastCgiServers = s;
}

/*******************************************************************************
 * Configure uid, gid, user, group, username for suexec.
 */
static const char *server_setUidGid(pool *p, FastCgiServerInfo *s,
                                    uid_t uid, gid_t gid)
{
    struct passwd *pw;
    struct group  *gr;

    if (fcgi_suexec == NULL)
        return NULL;

    s->uid = uid;
    pw = getpwuid(uid);
    if (pw == NULL) {
        return psprintf(p,
            "getpwuid() couldn't determine the username for uid '%ld', "
            "you probably need to modify the User directive: %s",
            (long)uid, strerror(errno));
    }
    s->user = pstrdup(p, pw->pw_name);
    s->username = s->user;

    s->gid = gid;
    gr = getgrgid(gid);
    if (gr == NULL) {
        return psprintf(p,
            "getgrgid() couldn't determine the group name for gid '%ld', "
            "you probably need to modify the Group directive: %s",
            (long)gid, strerror(errno));
    }
    s->group = pstrdup(p, gr->gr_name);

    return NULL;
}

/*******************************************************************************
 * Allocate an array of ServerProcess records.
 */
static ServerProcess *server_createProcs(pool *p, int num)
{
    int i;
    ServerProcess *proc = (ServerProcess *)pcalloc(p, sizeof(ServerProcess) * num);

    for (i = 0; i < num; i++) {
        proc[i].pid = 0;
        proc[i].state = STATE_READY;
    }
    return proc;
}

/*******************************************************************************
 * Send SIGTERM to each process in the server class, remove socket and lock
 * file if appropriate.  Currently this is only called when the PM is shutting
 * down and thus memory isn't freed and sockets and files aren't closed.
 */
static void server_shutdown(pool *p, FastCgiServerInfo *s)
{
    ServerProcess *proc = s->procs;
    int i, numChildren;

    if (s->directive == APP_CLASS_DYNAMIC)
        numChildren = dynamicMaxClassProcs;
    else
        numChildren = s->numProcesses;

    for (i = 0; i < numChildren; i++, proc++) {
        if (proc->pid > 0) {
            kill(proc->pid, SIGTERM);
            proc->pid = -1;
        }
    }

    /* Remove the dead lock file */
    if (s->directive == APP_CLASS_DYNAMIC) {
        const char *lockFileName = dynamic_makeLockPath(p, s->sockPath);

        if (unlink(lockFileName) != 0) {
            fprintf(errorLog, "[%s] mod_fastcgi: "
                "unlink() failed to remove lock file '%s' for app '%s': %s\n",
                get_time(), lockFileName, s->execPath,
                strerror(errno));
        }
    }

    /* Remove the socket file */
    if (s->sockPath != NULL && s->directive != APP_CLASS_EXTERNAL) {
        if (unlink(s->sockPath) != 0) {
            fprintf(errorLog, "[%s] mod_fastcgi: "
                "unlink() failed to remove socket file '%s' for app '%s': %s\n",
                get_time(), s->sockPath, s->execPath,
                strerror(errno));
            fflush(errorLog);
        }
    }
    fastCgiServers = s->next;
}

/*******************************************************************************
 * Get the next configuration directive argument, & return an in_addr and port.
 * The arg must be in the form "host:port" where host can be an IP or hostname.
 * The pool arg should be persistant storage.
 */
static const char *conf_getHostPort(pool *p, const char **arg,
        const char **host, u_int *port)
{
    char *cvptr, *portStr;

    *host = getword_conf(p, arg);
    portStr = strchr(*host, ':');

    if (!*host)
        return "\"\"";
    if (!portStr)
        return "missing port specification";

    /* Split the host and port portions */
    *portStr++ = '\0';

    /* Convert port number */
    *port = (u_int)strtol(portStr, &cvptr, 10);
    if (*cvptr != '\0' || *port < 1 || *port > 65535)
        return pstrcat(p, "bad port number \"", portStr, "\"", NULL);

    return NULL;
}

/*******************************************************************************
 * Get the next configuration directive argument, & return an u_int.
 * The pool arg should be temporary storage.
 */
static const char *conf_getUInt(pool *p, const char **arg,
        u_int *num, u_int min)
{
    char *ptr;
    const char *val = getword_conf(p, arg);

    if (!*val)
        return "\"\"";
    *num = (u_int)strtol(val, &ptr, 10);

    if (*ptr)
        return pstrcat(p, "\"", val, "\" must be a positive integer", NULL);
    else if (*num < min)
        return psprintf(p, "\"%u\" must be >= %u", *num, min);
    return NULL;
}

/*******************************************************************************
 * Get the next configuration directive argument, & return a float.
 * The pool arg should be temporary storage.
 */
static const char *conf_getFloat(pool *p, const char **arg,
        float *num, float min, float max)
{
    char *ptr;
    const char *val = getword_conf(p, arg);

    if (!*val)
        return "\"\"";
    *num = strtod(val, &ptr);

    if (*ptr)
        return pstrcat(p, "\"", val, "\" is not a floating point number", NULL);
    if (*num < min || *num > max)
        return psprintf(p, "\"%f\" is not between %f and %f", *num, min, max);
    return NULL;
}

/*******************************************************************************
 * Get the next configuration directive argument, & add it to an env array.
 * The pool arg should be permanent storage.
 */
static const char *conf_getEnv(pool *p, const char **arg,
        const char ***envp, int *envc)
{
    const char *val = getword_conf(p, arg);

    if (*val == '\0')
        return "\"\"";
    if (strchr(val, '=') == NULL)
        return pstrcat(p, "\"", val, "\" must contain an '='", NULL);
    if (*envc >= MAX_INIT_ENV_VARS)
        return "too many variables, must be <= MAX_INIT_ENV_VARS";
    **envp = val;
    (*envp)++;
    (*envc)++;
    return NULL;
}

/*******************************************************************************
 * Return a "standard" message for common configuration errors.
 */
static const char *conf_invalidValue(pool *p, const char *cmd, const char *id,
                               const char *opt, const char *err)
{
    return psprintf(p, "%s%s%s: invalid value for %s: %s",
                    cmd, id ? " " : "", id ? id : "",  opt, err);
}

/*******************************************************************************
 * Set/Reset the uid/gid that Apache and the PM will run as.  This is user_id
 * and group_id if we're started as root, and euid/egid otherwise.  Also try
 * to check that the config files don't set the User/Group after a FastCGI
 * directive is used that depends on it.
 */
/*@@@ To be complete, we should save a handle to the server each AppClass is
 * configured in and at init() check that the user/group is still what we
 * thought it was.  Also the other directives should only be allowed in the
 * parent Apache server.
 */
static char *conf_setFcgiUidGid(int set)
{
    static int isSet = 0;
    uid_t uid = geteuid();
    gid_t gid = getegid();

    if (set == 0) {
        isSet = 0;
        fcgi_user_id = (uid_t)-1;
        fcgi_group_id = (gid_t)-1;
        return NULL;
    }

    uid = uid ? uid : user_id;
    gid = uid ? gid : group_id;

    if (isSet && (uid != fcgi_user_id || gid != fcgi_group_id)) {
        return "User/Group commands must preceed FastCGI server definitions";
    }

    isSet = 1;
    fcgi_user_id = uid;
    fcgi_group_id = gid;
    return NULL;
}

static void conf_reset(void* dummy)
{
    fcgiPool = NULL;
    fastCgiServers = NULL;
    conf_setFcgiUidGid(0);
    fcgi_suexec = NULL;
    ipcDir = DEFAULT_SOCK_DIR;
    globalNumInstances = 0;

    dynamicMaxProcs = FCGI_DEFAULT_MAX_PROCS;
    dynamicMinProcs = FCGI_DEFAULT_MIN_PROCS;
    dynamicMaxClassProcs = FCGI_DEFAULT_MAX_CLASS_PROCS;
    dynamicKillInterval = FCGI_DEFAULT_KILL_INTERVAL;
    dynamicUpdateInterval = FCGI_DEFAULT_UPDATE_INTERVAL;
    dynamicGain = FCGI_DEFAULT_GAIN;
    dynamicThreshhold1 = FCGI_DEFAULT_THRESHHOLD_1;
    dynamicThreshholdN = FCGI_DEFAULT_THRESHHOLD_N;
    dynamicPleaseStartDelay = FCGI_DEFAULT_START_PROCESS_DELAY;
    dynamicAppConnectTimeout = FCGI_DEFAULT_APP_CONN_TIMEOUT;
    dynamicEnvp = NULL;
    dynamicProcessSlack = FCGI_DEFAULT_PROCESS_SLACK;
    dynamicAutoRestart = FCGI_DEFAULT_RESTART_DYNAMIC;
    dynamicAutoUpdate = FCGI_DEFAULT_AUTOUPDATE;
    dynamicListenQueueDepth = FCGI_DEFAULT_LISTEN_Q;
    dynamicInitStartDelay = DEFAULT_INIT_START_DELAY;
    dynamicRestartDelay = FCGI_DEFAULT_RESTART_DELAY;
}

/*******************************************************************************
 * Create a directory to hold Unix/Domain sockets.
 */
static const char *conf_createDir(pool *tp, char *path)
{
    struct stat finfo;

    /* Is the directory spec'd correctly */
    if (*path != '/') {
        return "path is not absolute (it must start with a \"/\")";
    }
    else {
        int i = strlen(path) - 1;

        /* Strip trailing "/"s */
        while(i > 0 && path[i] == '/') path[i--] = '\0';
    }

    /* Does it exist? */
    if (stat(path, &finfo) != 0) {
        /* No, but maybe we can create it */
        if (mkdir(path, S_IRWXU) != 0) {
            return psprintf(tp,
                "doesn't exist and can't be created: %s",
                strerror(errno));
        }

        /* If we're root, we're gonna setuid/setgid so we need to chown */
        if (geteuid() == 0 && chown(path, user_id, group_id) != 0) {
            return psprintf(tp,
                "can't chown() to the server (uid %ld, gid %ld): %s",
                (long)user_id, (long)group_id, strerror(errno));
        }
    }
    else {
        /* Yes, is it a directory? */
        if (!S_ISDIR(finfo.st_mode))
            return "isn't a directory!";

        /* Can we RWX in there? */
        if (WS_Access(NULL, &finfo, R_OK | W_OK | X_OK,
                        fcgi_user_id, fcgi_group_id) != 0) {
            return psprintf(tp,
                "doesn't allow read/write/execute by the server (uid %ld, gid %ld)",
                (long)fcgi_user_id, (long)fcgi_group_id);
        }
    }
    return NULL;
}

/*******************************************************************************
 * Create a "dynamic" subdirectory and mbox (used for RH->PM comm) in the
 * ipcDir with appropriate permissions.
 */
static const char *conf_createDynamicDirAndMbox(pool *p)
{
    DIR *dp = NULL;
    struct dirent *dirp = NULL;
    int fd;
    const char *err;
    pool *tp;

    ipcDynamicDir = pstrcat(p, ipcDir, "/dynamic", NULL);

    err = conf_createDir(p, ipcDynamicDir);
    if (err != NULL) {
        return psprintf(p,
            "can't create dynamic directory \"%s\": %s",
            ipcDynamicDir, err);
    }

    /* Create a subpool for the directory operations */
    tp = make_sub_pool(p);

    dp = popendir(tp, ipcDynamicDir);
    if (dp == NULL) {
        destroy_pool(tp);
        return psprintf(p, "can't open dynamic directory \"%s\": %s",
            ipcDynamicDir, strerror(errno));
    }

    /* Delete everything in the directory, its all FCGI specific */
    while ((dirp = readdir(dp)) != NULL) {
        if (strcmp(dirp->d_name, ".") == 0
                || strcmp(dirp->d_name, "..") == 0) {
            continue;
        }

        unlink(pstrcat(tp, ipcDynamicDir, "/", dirp->d_name, NULL));
    }

    destroy_pool(tp);

    /* Create mbox */
    mbox = pstrcat(p, ipcDynamicDir, "/mbox", NULL);

    /* @@@ This really should be a socket or pipe */
    fd = popenf(p, mbox, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return psprintf(p, "can't create \"%s\": %s",
            mbox, strerror(errno));
    }

    /* If we're root, were gonna setuid/setgid so chown */
    if (geteuid() == 0 && fchown(fd, user_id, group_id) != 0) {
        return psprintf(p,
            "can't chown() \"%s\" to server (uid %ld, gid %ld): %s",
            mbox, (long)user_id, (long)group_id, strerror(errno));
    }
    pclosef(p, fd);

    return NULL;
}


/*******************************************************************************
 * Change the directory used for the Unix/Domain sockets from the default.
 * Create the directory, the "dynamic" subdirectory, and the mbox used for
 * comm between the RH and the PM (we do this here, as well as in
 * ModFastCgiInit, so we can prevent Apache from starting if it fails).
 */
const char *conf_FastCgiIpcDir(cmd_parms *cmd, void *dummy, char *arg)
{
    pool * const tp = cmd->temp_pool;
    const char * const name = cmd->cmd->name;
    const char *err;

    if (strcmp(ipcDir, DEFAULT_SOCK_DIR) != 0) {
        return psprintf(tp, "%s %s: already defined as \"%s\"",
                        name, arg, ipcDir);
    }

    err = conf_setFcgiUidGid(1);
    if (err != NULL)
        return psprintf(tp, "%s %s: %s", name, arg, err);

    if (fastCgiServers != NULL) {
        return psprintf(tp,
            "The %s command must preceed static FastCGI server definitions",
            name);
    }

    ipcDir = arg;

    err = conf_createDir(tp, ipcDir);
    if (err != NULL)
        return psprintf(tp, "%s %s: %s", name, arg, err);

    err = conf_createDynamicDirAndMbox(cmd->pool);
    if (err != NULL)
        return psprintf(tp, "%s %s: %s", name, arg, err);

    return NULL;
}

/*******************************************************************************
 * Enable, disable, or specify the path to the suexec program.
 */
const char *conf_FastCgiSuexec(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = NULL;
    const char * const name = cmd->cmd->name;
    pool * const tp = cmd->temp_pool;

    if (!suexec_enabled) {
        if (strcasecmp(arg, "Off") != 0) {
	    fprintf(stderr,
		    "Warning: %s requires SUEXEC wrapper be enabled in Apache\n", name);
	}
	return NULL;
    }

    err = conf_setFcgiUidGid(1);
    if (err != NULL)
        return psprintf(tp, "%s %s: %s", name, arg, err);

    if (fastCgiServers != NULL) {
        return psprintf(tp,
            "The %s command must preceed static FastCGI server definitions",
            name);
    }

    if (strcasecmp(arg, "On") == 0) {
        fcgi_suexec = SUEXEC_BIN;
    }
    else if (strcasecmp(arg, "Off") == 0) {
    }
    else if (arg[0] != '/') {
        return psprintf(tp,
			"%s %s: path is not absolute (it must start with a \"/\")",
			name, arg);
    }
    else {
        if (WS_Access(arg, NULL, X_OK, fcgi_user_id, fcgi_group_id) != 0) {
            return psprintf(tp,
                "%s: \"%s\" is not executable by server (uid %ld, gid %ld)",
                name, arg, (long)fcgi_user_id, (long)fcgi_group_id);
        }

        fcgi_suexec = arg;
    }
    return NULL;
}

/*******************************************************************************
 * Configure a static FastCGI server.
 */
const char *conf_AppClass(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char **envp;
    int envc = 0;
    FastCgiServerInfo *s;
    pool *p = cmd->pool, *tp = cmd->temp_pool;
    const char *name = cmd->cmd->name;
    const char *execPath = getword_conf(p, &arg);
    const char *option, *err;

    if (*execPath == '\0')
        return "AppClass requires a pathname!?";

    err = conf_setFcgiUidGid(1);
    if (err != NULL)
        return psprintf(tp, "%s %s: %s", name, execPath, err);

    /* See if we've already got one of these configured */
    s = server_getById(execPath, cmd->server->server_uid,
                       cmd->server->server_uid);
    if (s != NULL) {
        if (fcgi_suexec) {
            return psprintf(tp,
                "%s: redefinition of a previously defined FastCGI server \"%s\" with uid=%ld and gid=%ld",
                name, execPath, (long)cmd->server->server_uid,
                (long)cmd->server->server_gid);
        }
        else {
            return psprintf(tp,
                "%s; redefinition of a previously defined FastCGI server \"%s\"",
                name, execPath);
        }
    }

    if (fcgi_suexec != NULL) {
        if (WS_Access(execPath, NULL, X_OK, cmd->server->server_uid,
                      cmd->server->server_uid)) {
            return psprintf(tp,
                "%s %s: not executable by fcgi_suexec (uid %ld, gid %ld)",
                name, execPath, (long)cmd->server->server_uid,
                (long)cmd->server->server_uid);
        }
    }
    else {
        if (WS_Access(execPath, NULL, X_OK, fcgi_user_id, fcgi_group_id)) {
            return psprintf(tp,
                "%s %s: not executable by server (uid %ld, gid %ld)",
                name, execPath, (long)fcgi_user_id, (long)fcgi_group_id);
        }
    }

    s = server_new(p);
    s->execPath = execPath;
    s->directive = APP_CLASS_STANDARD;
    s->restartOnExit = TRUE;
    s->numProcesses = 1;

    /* Allocate temp storage for the array of initial environment variables */
    envp = pcalloc(tp, sizeof(char *) * MAX_INIT_ENV_VARS);
    s->envp = (const char * const *)envp;

    if (fcgi_suexec) {
        struct passwd *pw;
        struct group  *gr;

        s->uid = cmd->server->server_uid;
        pw = getpwuid(s->uid);
        if (pw == NULL) {
            return psprintf(tp, "mod_fastcgi: "
                "getpwuid() couldn't determine the username for uid '%ld', "
                "you probably need to modify the User directive: %s",
                (long)s->uid, strerror(errno));
        }
        s->user = pstrdup(p, pw->pw_name);
        s->username = s->user;

        s->gid = cmd->server->server_gid;
        gr = getgrgid(s->gid);
        if (gr == NULL) {
            return psprintf(tp, "mod_fastcgi: "
                "getgrgid() couldn't determine the group name for gid '%ld', "
                "you probably need to modify the Group directive: %s\n",
                (long)s->gid, strerror(errno));
        }
        s->group = pstrdup(p, gr->gr_name);
    }

    /*  Parse directive arguments */
    while (*arg) {
        option = getword_conf(tp, &arg);

        if (strcmp(option, "-processes") == 0) {
            err = conf_getUInt(tp, &arg, &s->numProcesses, 1);
            if (err != NULL)
                return conf_invalidValue(tp, name, execPath, option, err);
            continue;
        }
        else if (strcmp(option, "-restart-delay") == 0) {
            err = conf_getUInt(tp, &arg, &s->restartDelay, 0);
            if (err != NULL)
                return conf_invalidValue(tp, name, execPath, option, err);
            continue;
        }
        else if (strcmp(option, "-init-start-delay") == 0) {
            err = conf_getUInt(tp, &arg, &s->initStartDelay, 0);
            if (err != NULL)
                return conf_invalidValue(tp, name, execPath, option, err);
            continue;
        }
        else if (strcmp(option, "-priority") == 0) {
            err = conf_getUInt(tp, &arg, &s->processPriority, 0);
            if (err != NULL)
                return conf_invalidValue(tp, name, execPath, option, err);
            continue;
        }
        else if (strcmp(option, "-listen-queue-depth") == 0) {
            err = conf_getUInt(tp, &arg, &s->listenQueueDepth, 1);
            if (err != NULL)
                return conf_invalidValue(tp, name, execPath, option, err);
            continue;
        }
        else if (strcmp(option, "-appConnTimeout") == 0) {
            err = conf_getUInt(tp, &arg, &s->appConnectTimeout, 0);
            if (err != NULL)
                return conf_invalidValue(tp, name, execPath, option, err);
            continue;
        }
        else if (strcmp(option, "-port") == 0) {
            err = conf_getUInt(tp, &arg, &s->port, 1);
            if (err != NULL)
                return conf_invalidValue(tp, name, execPath, option, err);
            continue;
        }
        else if (strcmp(option, "-socket") == 0) {
            s->sockPath = getword_conf(tp, &arg);
            if (*s->sockPath == '\0')
                return conf_invalidValue(tp, name, execPath, option, "\"\"");
            continue;
        }
        else if (strcmp(option, "-initial-env") == 0) {
            err = conf_getEnv(p, &arg, &envp, &envc);
            if (err != NULL)
                return conf_invalidValue(tp, name, execPath, option, err);
            continue;
        }
        else
            return conf_invalidValue(tp, name, execPath, option, NULL);
    } /* while */

    if (s->sockPath != NULL && s->port != 0) {
        return psprintf(tp,
                "%s %s: -port and -socket are mutually exclusive options",
                name, execPath);
    }

    /* If -intial-env option was used, move env array to a surviving pool */
    if (envc != 0)
        s->envp = (const char **)pstrdup(p, *s->envp);
    else
        s->envp = NULL;

    /* Initialize process structs */
    s->procs = server_createProcs(p, s->numProcesses);

    /* Build the appropriate sockaddr structure */
    if (s->port != 0) {
        err = sock_makeInetAddr(p, (struct sockaddr_in **)&s->sockAddr,
                                &s->sockAddrLen, NULL, s->port);
        if (err != NULL)
            return psprintf(tp, "%s %s: %s", name, execPath, err);
    } else {
        if (s->sockPath == NULL)
             s->sockPath = sock_makeHash(tp, execPath, s->user, s->group);
        s->sockPath = sock_makePath(p, s->sockPath, 0);
        err = sock_makeDomainAddr(p, (struct sockaddr_un **)&s->sockAddr,
                                  &s->sockAddrLen, s->sockPath);
        if (err != NULL)
            return psprintf(tp, "%s %s: %s", name, execPath, err);
    }

    /* Add it to the list of FastCGI servers */
    server_add(s);

    return NULL;
}

/*******************************************************************************
 * Configure a static FastCGI server that is started/managed elsewhere.
 */
const char *conf_ExternalAppClass(cmd_parms *cmd, void *dummy, const char *arg)
{
    FastCgiServerInfo *s;
    pool * const p = cmd->pool, *tp = cmd->temp_pool;
    const char * const name = cmd->cmd->name;
    const char *execPath = getword_conf(p, &arg);
    const char *option, *err;

    if (!*execPath) {
        return pstrcat(tp, name,
            " requires a path and either a -socket or -host option", NULL);
    }
    /* See if we've already got one of these bettys configured */
    s = server_getById(execPath, cmd->server->server_uid,
                       cmd->server->server_gid);
    if (s != NULL) {
        if (fcgi_suexec != NULL) {
            return psprintf(tp,
                "%s: redefinition of a previously defined class \"%s\" with uid=%ld and gid=%ld",
                name, execPath, (long)cmd->server->server_uid,
                (long)cmd->server->server_gid);
        }
        else {
            return psprintf(tp,
                "%s: redefinition of previously defined class \"%s\"",
                name, execPath);
        }
    }

    s = server_new(p);
    s->execPath = execPath;
    s->directive = APP_CLASS_EXTERNAL;

    err = server_setUidGid(p, s, cmd->server->server_uid, cmd->server->server_gid);
    if (err != NULL)
        return psprintf(tp, "%s %s: %s", name, execPath, err);

    /*  Parse directive arguments */
    while (*arg != '\0') {
        option = getword_conf(tp, &arg);

        if (strcmp(option, "-host") == 0) {
            err = conf_getHostPort(p, &arg, &s->host, &s->port);
            if (err != NULL)
                return conf_invalidValue(tp, name, execPath, option, err);
            continue;
        }
        else if (strcmp(option, "-socket") == 0) {
            s->sockPath = getword_conf(tp, &arg);
            if (*s->sockPath == '\0')
                return conf_invalidValue(tp, name, execPath, option, "\"\"");
            continue;
        }
        else if (strcmp(option, "-appConnTimeout") == 0) {
            err = conf_getUInt(tp, &arg, &s->appConnectTimeout, 0);
            if (err != NULL)
                return conf_invalidValue(tp, name, execPath, option, err);
            continue;
        }
        else {
            return psprintf(tp, "%s %s: invalid option: %s",
                            name, execPath, option);
        }
    } /* while */

    /* Require one of -socket or -host, but not both */
    if (s->sockPath != NULL && s->port != 0) {
        return psprintf(tp,
            "%s %s: -host and -socket are mutually exclusive options",
            name, execPath);
    }
    if (s->sockPath == NULL && s->port == 0) {
        return psprintf(tp,
            "%s %s: -socket or -host option missing", name, execPath);
    }

    /* Build the appropriate sockaddr structure */
    if (s->port != 0) {
        err = sock_makeInetAddr(p, (struct sockaddr_in **)&s->sockAddr,
                                &s->sockAddrLen, NULL, s->port);
        if (err != NULL)
            return psprintf(tp, "%s %s: %s", name, execPath, err);
    } else {
        s->sockPath = sock_makePath(p, s->sockPath, 0);
        err = sock_makeDomainAddr(p, (struct sockaddr_un **)&s->sockAddr,
                                  &s->sockAddrLen, s->sockPath);
        if (err != NULL)
            return psprintf(tp, "%s %s: %s", name, execPath, err);
    }

    /* Add it to the list of FastCGI servers */
    server_add(s);

    return NULL;
}

/*
 *----------------------------------------------------------------------
 *
 * conf_FCGIConfig --
 *
 *      Implements the FastCGI FCGIConfig configuration directive.
 *      This command adds routines to control the execution of the
 *      dynamic FastCGI processes.
 *
 *
 *----------------------------------------------------------------------
 */
const char *conf_FCGIConfig(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char **envp;
    int envc = 0;
    pool * const p = cmd->pool;
    pool * const tp = cmd->temp_pool;
    const char *err, *option;
    const char * const name = cmd->cmd->name;

    /* Allocate temp storage for an initial environment */
    envp = pcalloc(tp, sizeof(char *) * MAX_INIT_ENV_VARS);
    dynamicEnvp = (const char * const *)envp;

    /* Parse the directive arguments */
    while (*arg) {
        option = getword_conf(tp, &arg);

        if (strcmp(option, "-maxProcesses") == 0) {
            err = conf_getUInt(tp, &arg, &dynamicMaxProcs, 1);
            if (err != NULL)
                return conf_invalidValue(tp, name, NULL, option, err);
            continue;
        }
        else if (strcmp(option, "-minProcesses") == 0) {
            err = conf_getUInt(tp, &arg, &dynamicMinProcs, 0);
            if (err != NULL)
                return conf_invalidValue(tp, name, NULL, option, err);
            continue;
        }
        else if (strcmp(option, "-maxClassProcesses") == 0) {
            err = conf_getUInt(tp, &arg, &dynamicMaxClassProcs, 1);
            if (err != NULL)
                return conf_invalidValue(tp, name, NULL, option, err);
            continue;
        }
        else if (strcmp(option, "-killInterval") == 0) {
            err = conf_getUInt(tp, &arg, &dynamicKillInterval, 1);
            if (err != NULL)
                return conf_invalidValue(tp, name, NULL, option, err);
            continue;
        }
        else if (strcmp(option, "-updateInterval") == 0) {
            err = conf_getUInt(tp, &arg, &dynamicUpdateInterval, 1);
            if (err != NULL)
                return conf_invalidValue(tp, name, NULL, option, err);
            continue;
        }
        else if (strcmp(option, "-gainValue") == 0) {
            err = conf_getFloat(tp, &arg, &dynamicGain, 0.0, 1.0);
            if (err != NULL)
                return conf_invalidValue(tp, name, NULL, option, err);
            continue;
        }
        else if (strcmp(option, "-singleThreshhold") == 0) {
            err = conf_getUInt(tp, &arg, &dynamicThreshhold1, 1);
            if (err != NULL)
                return conf_invalidValue(tp, name, NULL, option, err);
            continue;
        }
        else if (strcmp(option, "-multiThreshhold") == 0) {
            err = conf_getUInt(tp, &arg, &dynamicThreshholdN, 1);
            if (err != NULL)
                return conf_invalidValue(tp, name, NULL, option, err);
            continue;
        }
        else if (strcmp(option, "-startDelay") == 0) {
            err = conf_getUInt(tp, &arg, &dynamicPleaseStartDelay, 1);
            if (err != NULL)
                return conf_invalidValue(tp, name, NULL, option, err);
            continue;
        }
        else if (strcmp(option, "-initial-env") == 0) {
            err = conf_getEnv(p, &arg, &envp, &envc);
            if (err != NULL)
                return conf_invalidValue(tp, name, NULL, option, err);
            continue;
        }
        else if (strcmp(option, "-appConnTimeout") == 0) {
            err = conf_getUInt(tp, &arg, &dynamicAppConnectTimeout, 0);
            if (err != NULL)
                return conf_invalidValue(tp, name, NULL, option, err);
            continue;
        }
        else if (strcmp(option, "-listen-queue-depth") == 0) {
            err = conf_getUInt(tp, &arg, &dynamicListenQueueDepth, 1);
            if (err != NULL)
                return conf_invalidValue(tp, name, NULL, option, err);
            continue;
        }
        else if (strcmp(option, "-restart-delay") == 0) {
            err = conf_getUInt(tp, &arg, &dynamicRestartDelay, 0);
            if (err != NULL)
                return conf_invalidValue(tp, name, NULL, option, err);
            continue;
        }
        else if (strcmp(option, "-init-start-delay") == 0) {
            err = conf_getUInt(tp, &arg, &dynamicInitStartDelay, 0);
            if (err != NULL)
                return conf_invalidValue(tp, name, NULL, option, err);
            continue;
        }
        else if (strcmp(option, "-processSlack") == 0) {
            err = conf_getUInt(tp, &arg, &dynamicProcessSlack, 1);
            if (err != NULL)
                return conf_invalidValue(tp, name, NULL, option, err);
            continue;
        }
        else if (strcmp(option, "-restart") == 0) {
            dynamicAutoRestart = 1;
            continue;
        }
        else if (strcmp(option, "-autoUpdate") == 0) {
            dynamicAutoUpdate = 1;
            continue;
        }
        else {
            return psprintf(tp, "%s: invalid option: %s", name, option);
        }
    } /* while */

    /* If -intial-env option was used, move env array to a surviving pool */
    if (envc != 0) {
        dynamicEnvp = (const char * const *)pstrdup(p, (char *)dynamicEnvp);
    }
    else {
        dynamicEnvp = NULL;
    }

    return NULL;
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

/* *** This may be a problem for Apache request handling processes,
    the soft_timeout() causes an alarm to go off which causes the
    abort of the request - we need to be able to get out of here,
    at least for dynamic apps. */
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

int AddNewRecord(pool *p, char id, char* execPath, const char *user,
         const char *group, unsigned long qsecs,
         unsigned long ctime, unsigned long now)
{
    int fd, size, status;
    char buf[TMP_BUFSIZ];

    memset(buf, 0, TMP_BUFSIZ);
    switch(id) {
        case PLEASE_START:
                sprintf(buf, "%c %s %s %s\n",
                id, execPath, user, group);
                break;
        case CONN_TIMEOUT:
                sprintf(buf, "%c %s %s %s %lu\n",
                id, execPath, user, group, qsecs);
                break;
        case REQ_COMPLETE:
                sprintf(buf, "%c %s %lu %lu %lu\n",
                id, execPath, qsecs, ctime, now);
                break;
    }

    /* figure out how big the buffer is */
    size = (strchr((const char *)buf, '\n')-buf)+1;
    ASSERT(size>0);

    if((fd = popenf(p, mbox, O_WRONLY|O_APPEND, 0))<0) {
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
    pclosef(p, fd);
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

int RemoveRecords(void)
{
    FastCgiServerInfo *s;
    struct stat statbuf;
    int recs = -1, fd, i;
    char *buf=NULL, opcode;
    char *ptr1=NULL, *ptr2=NULL;
    char execName[TMP_BUFSIZ];
    char user[17];
    char group[16];
    unsigned long qsec = 0, ctime = 0; /* microseconds spent waiting for the
                                        * application, and spent using it */
    time_t now = time(NULL);
    pool *sp;
    pool * const tp = make_sub_pool(fcgiPool);

    user[17] = group[16] = '\0';

    /* Obtain the data from the mbox file */
    if ((fd = popenf(tp, mbox, O_RDWR, S_IRUSR | S_IWUSR)) < 0) {
        fprintf(errorLog,
                "[%s] mod_fastcgi: unable to open mbox: %s\n",
                get_time(), strerror(errno));
        goto CleanupReturn;
    }
    WritewLock(fd);
    if(fstat(fd, &statbuf)<0) {
        fprintf(errorLog, "errno = %d\n", (errno));
        fprintf(errorLog,
                "[%s] mod_fastcgi: Unable to fstat() mbox\n", get_time());
        goto NothingToDo;
    }
    buf = pcalloc(tp, statbuf.st_size + 1);
    if(statbuf.st_size==0) {
        recs = 0;
        goto NothingToDo;
    }
    if(read(fd, (void *)buf, statbuf.st_size)<statbuf.st_size) {
        fprintf(errorLog,
                "[%s] mod_fastcgi: Read failed for mbox\n", get_time());
        goto NothingToDo;
    }
    if(ftruncate(fd, 0)<0) {
        fprintf(errorLog,
                "[%s] mod_fastcgi: Unable to ftruncate() mbox\n", get_time());
        goto NothingToDo;
    }

    recs = 1;

NothingToDo:
    pclosef(tp, fd);
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
    if((long)(now-lastAnalyze)>=dynamicUpdateInterval) {
        for(s=fastCgiServers;s!=NULL;s=s->next) {
            /* XXX what does this adjustment do? */
            lastAnalyze += (((long)(now-lastAnalyze)/dynamicUpdateInterval)*dynamicUpdateInterval);
            s->smoothConnTime = (1.0-dynamicGain)*s->smoothConnTime + dynamicGain*s->totalConnTime;
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
                sscanf(ptr1, "%c %s %16s %15s\n", &opcode, execName, user, group);
                break;
            case CONN_TIMEOUT:
                sscanf(ptr1, "%c %s %16s %15s %lu\n", &opcode, execName, user, group, &qsec);
                break;
            case REQ_COMPLETE:
                sscanf(ptr1, "%c %s %16s %15s %lu %lu %lu\n", &opcode,
                       execName, user, group, &qsec, &ctime, &now);
                break;
            default:
                goto CleanupReturn;
                break;
        }

        s = server_get(execName, user, group);

        if (s==NULL && opcode != REQ_COMPLETE) {
            const char *err, *lockPath;

            /* Create a perm subpool to hold the new server data,
             * we can destroy it if something doesn't pan out */
            sp = make_sub_pool(fcgiPool);

            /* Create a new "dynamic" server */
            s = server_new(sp);
            s->directive = APP_CLASS_DYNAMIC;
            s->restartDelay = dynamicRestartDelay;
            s->initStartDelay = dynamicInitStartDelay;
            s->envp = dynamicEnvp;
            s->execPath = pstrdup(sp, execName);
            s->procs = server_createProcs(sp, dynamicMaxClassProcs);

            /* Create socket file's path */
            s->sockPath = sock_makeHash(tp, execName, user, group);
            s->sockPath = sock_makePath(sp, s->sockPath, 1);

            /* Create sockaddr, prealloc it so it won't get created in tp */
            s->sockAddr = pcalloc(sp, sizeof(struct sockaddr_un));
            err = sock_makeDomainAddr(tp, (struct sockaddr_un **)&s->sockAddr,
                                      &s->sockAddrLen, s->sockPath);
            if (err) {
                ap_log_error(FCGI_LOG_ERR, NULL,
                          "FastCGI: failed to create dynamic server"
                          " \"%s\": %s", execName, err);
                goto BagNewServer;
            }

            /* Create the socket */
            if ((s->listenFd =
                    psocket(sp, s->sockAddr->sa_family, SOCK_STREAM, 0)) < 0) {
                ap_log_error(FCGI_LOG_ERR, NULL,
                          "FastCGI: failed to create dynamic server"
                          " \"%s\": can't create socket: %s",
                          execName, strerror(errno));
                goto BagNewServer;
            }

            /* bind() and listen() */
            err = sock_bindAndListen(tp, s->sockAddr, s->sockAddrLen,
                                     s->listenQueueDepth, s->listenFd);
            if (err) {
                ap_log_error(FCGI_LOG_ERR, NULL,
                          "FastCGI: failed to create dynamic server"
                          " \"%s\": %s", execName, err);
                goto BagNewServer;
            }

            /* Create the lock file */
            lockPath = dynamic_makeLockPath(tp, s->sockPath);
            fd = popenf(tp, lockPath,
                       O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
            if (fd < 0) {
                ap_log_error(FCGI_LOG_ERR, NULL,
                          "FastCGI: failed to create dynamic server"
                          " \"%s\": can't create/open lock file \"%s\": %s",
                          execName, lockPath, err);
                goto BagNewServer;
            }
            pclosef(tp, fd);

            /* If suexec is being used, config user/group info */
            if (fcgi_suexec) {
                if (user[0] == '~') {
                    /* its a user dir uri, the rest is a username, not a uid */
                    struct passwd *pw = getpwnam(&user[1]);

                    if (!pw) {
                        ap_log_error(FCGI_LOG_ERR, NULL,
                                  "FastCGI: can't get uid for username  \"%s\": %s",
                                  &user[1], strerror(errno));
                        goto BagNewServer;
                    }
                    s->uid = pw->pw_uid;
                    s->user = pstrdup(sp, user);
                    s->username = s->user;

                    s->gid = pw->pw_gid;
                    s->group = psprintf(sp, "%ld", (long)s->gid);
                }
                else {
                    struct passwd *pw;

                    s->uid = (uid_t)atol(user);
                    pw = getpwuid(s->uid);
                    if (!pw) {
                        ap_log_error(FCGI_LOG_ERR, NULL,
                                  "FastCGI: failed to create dynamic server"
                                  " \"%s\": can't get username for uid \"%ld\": %s",
                                  execName, (long)s->uid, strerror(errno));
                        goto BagNewServer;
                    }
                    s->user = pstrdup(sp, user);
                    s->username = pstrdup(sp, pw->pw_name);

                    s->gid = (gid_t)atol(group);
                    s->group = pstrdup(sp, group);
                }
            }
        server_add(s);
        } else {
            if(opcode==PLEASE_START) {
                if (dynamicAutoUpdate) {
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
                            numChildren = dynamicMaxClassProcs;
                        } else {
                            numChildren = s->numProcesses;
                        }
                        for (i = 0; i < s->numProcesses; i++) {
                            kill(s->procs[i].pid, SIGTERM);
                        }
                        fprintf(errorLog,
                                "mod_fastcgi: binary %s modified, restarting FCGI app server\n",
                                execName);
                    }

                    /* If dynamicAutoRestart, don't mark any new processes
                     * for  starting because we probably got the
                     * PLEASE_START due to dynamicAutoUpdate and the ProcMgr
                     * will be restarting all of those we just killed.
                     */
                    if (dynamicAutoRestart)
                        continue;
                } else {
                    /* we've been asked to start a process--only start
                    * it if we're not already running at least one
                    * instance.
                    */
                    int count = 0;
                    int numChildren;

                    /* see if any instances of this app are running */
                    if (s->directive == APP_CLASS_DYNAMIC) {
                        numChildren = dynamicMaxClassProcs;
                    } else {
                        numChildren = s->numProcesses;
                    }

                    for (i = 0; i < numChildren; i++) {
                        if (s->procs[i].state == STATE_STARTED)
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
                if((s->numProcesses+1)>dynamicMaxClassProcs) {
                    /* Can't do anything here, log error */
                    fprintf(errorLog,
                            "[%s] mod_fastcgi: Exceeded dynamicMaxClassProcs\n",
                            get_time());
                    continue;
                }
                if((globalNumInstances+1)>dynamicMaxProcs) {
                    /*
                     * Extra instances should have been
                     * terminated beforehand, probably need
                     * to increase ProcessSlack parameter
                     */
                    fprintf(errorLog,
                            "[%s] mod_fastcgi: Exceeded dynamicMaxProcs\n",
                            get_time());
                    continue;
                }
                /* find next free slot */
                for(i=0;i<dynamicMaxClassProcs;i++) {
                    if((s->procs[i].pid <= 0) &&
                            ((s->procs[i].state == STATE_READY) ||
                            (s->procs[i].state == STATE_NEEDS_STARTING) ||
                            (s->procs[i].state == STATE_KILLED)))
                        break;
                }
                ASSERT(i<dynamicMaxClassProcs);
                s->procs[i].state = STATE_NEEDS_STARTING;
                break;
            case REQ_COMPLETE:
                /* only record stats if we have a structure */
                if (s) {
                    s->totalConnTime += ctime;
                    s->totalQueueTime += qsec;
                }
                break;
        }

        continue;

BagNewServer:
        destroy_pool(sp);
    }

CleanupReturn:
    fflush(errorLog);
    destroy_pool(tp);
    return (recs);
}
#undef TMP_BUFSIZ


/* Information about a process we are doing a blocking kill of.  */
struct FuncData {
    const char *lockFileName;    /* name of the lock file to lock */
    pid_t pid;                   /* process to issue SIGTERM to   */
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
extern char *server_argv0;

void KillDynamicProcs()
{
    FastCgiServerInfo *s;
    struct FuncData *funcData = NULL;
    time_t now = time(NULL);
    float connTime;         /* server's smoothed running time, or
                             * if that's 0, the current total */
    float totalTime;        /* maximum number of microseconds that all
                             * of a server's running processes together
                             * could have spent running since the
                             * last check */
    float loadFactor;       /* percentage, 0-100, of totalTime that
                             * the processes actually used */
    int i, victims = 0;
    const char *lockFileName;
    int lockFd;
    pid_t pid;
    pool *tp = make_sub_pool(fcgiPool);

    /* pass 1 - locate and mark all victims */
    for(s=fastCgiServers;  s!=NULL; s=s->next) {
        /* Only kill dynamic apps */
        if (s->directive != APP_CLASS_DYNAMIC)
            continue;

        /* If the number of non-victims is less than or equal to
           the minimum that may be running without being killed off,
           don't select any more victims.  */
        if((globalNumInstances-victims)<=dynamicMinProcs) {
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
                < dynamicThreshholdN)) ||
                ((s->numProcesses==1) &&
                (loadFactor<dynamicThreshhold1))) {
            for(i=0;i<dynamicMaxClassProcs;i++) {
                /* if need to kill extra instance and have one that
                 * is not started yet, do not start it and skip */
                if(s->procs[i].state == STATE_NEEDS_STARTING) {
                    s->procs[i].state = STATE_READY;
                    victims++;
                    break;
                }
                if(s->procs[i].state == STATE_STARTED) {
                    s->procs[i].state = STATE_VICTIM;
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

        for(i = 0; i < dynamicMaxClassProcs; i++) {
            if(s->procs[i].state == STATE_VICTIM) {
                lockFileName = dynamic_makeLockPath(tp, s->execPath);
                if ((lockFd = popenf(tp, lockFileName, O_RDWR, 0))<0) {
                    /*
                     * If we need to kill an application and the
                     * corresponding lock file does not exist, then
                     * that means we are in big trouble here
                     */
                    /*@@@ this should be logged, but since all the lock
                     * file stuff will be tossed, I'll leave it now */
                    pclosef(tp, lockFd);
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
                    funcData = pcalloc(tp, sizeof(struct FuncData));
                    funcData->lockFileName = lockFileName;
                    funcData->pid = s->procs[i].pid;
                    /*
                     * We can not call onto spawn_child() here
                     * since we are completely disassociated from
                     * the web server, and must do process management
                     * directly.
                     */
                    if((pid=fork())<0) {
                        /*@@@ this should be logged, but since all the lock
                         * file stuff will be tossed, I'll leave it now */
                        destroy_pool(tp);
                        return;
                    } else if(pid==0) {
                        /* child */

                        /* rename the process for ps - best we can easily */
                        strncpy(server_argv0, "fcgiBlkKill", strlen(server_argv0));

                        BlockingKill(funcData);
                    } else {
                        /* parent */
                        pclosef(tp, lockFd);
                    }
                } else {
                    kill(s->procs[i].pid, SIGTERM);
                    pclosef(tp, lockFd);
                    break;
                }
            }
        }
    }
    destroy_pool(tp);
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
    errorLog = (FILE *)-1;
    if(errorLogPathname != NULL) {
        /*
         * errorLog = fopen(errorLogPathname, "a"),
         * but work around faulty implementations of fopen (SunOS)
         */
        int fd = popenf(fcgiPool, errorLogPathname, O_WRONLY | O_APPEND | O_CREAT,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
        if(fd >= 0) {
            errorLog = fdopen(fd, "a");
        }
    }
    if (errorLog == (FILE *)-1) {
        errorLog = fopen("/dev/null", "a");
    }
    return errorLog;
}

static void FastCgiProcMgrSignalHander(int signo)
{
    if ((signo == SIGTERM) || (signo == SIGUSR1) || (signo == SIGHUP)) {
        /* SIGUSR1 & SIGHUP are sent by apache to its process group
         * when apache get 'em.  Apache follows up (1.2.x) with attacks
         * on each of its child processes, but we've got the KillMgr
         * sitting between us so we never see the KILL.  The main loop
         * in ProcMgr also checks to see if the KillMgr has terminated,
         * and if it has, we handl it as if we should shutdown too. */
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

static int OS_ExecFcgiProgram(
        pid_t *childPid,
        int listenFd,
        int priority,
        const char *programName,
        const char * const *envPtr,
        const char *user,
        const char *group)
{
    int i;
    char *dirName;
    char *dnEnd, *failedSysCall;
    int save_errno;

    /*
     * Fork the fcgi process.
     */
    *childPid = fork();
    if(*childPid < 0) {
        return -1;
    } else if(*childPid != 0) {
        return 0;
    }

    /* We're the child.
     * We gonna exec() shortly so Apache pools don't matter */

    if(listenFd != FCGI_LISTENSOCK_FILENO) {
        dup2(listenFd, FCGI_LISTENSOCK_FILENO);
        close(listenFd);
    }

    dnEnd = strrchr(programName, '/');
    if (dnEnd == NULL) {
        dirName = "./";
    } else {
        dirName = pcalloc(fcgiPool, dnEnd - programName + 1);
        dirName = memcpy(dirName, programName, dnEnd - programName);
    }
    if (chdir(dirName) < 0) {
        failedSysCall = "chdir";
        goto FailedSystemCallExit;
    }

#ifndef __EMX__
     /* OS/2 dosen't support nice() */
    if(priority != 0) {
        if(nice(priority) == -1) {
            failedSysCall = "nice";
            goto FailedSystemCallExit;
        }
    }
#endif

    /*
     * Close any file descriptors we may have gotten from the parent
     * process.  The only FD left open is the FCGI listener socket.
     */
    for(i=0; i < MAX_OPEN_FDS; i++) {
        if(i != FCGI_LISTENSOCK_FILENO) {
            close(i);
        }
    }

    if (fcgi_suexec != NULL) {
        char *shortName = strrchr(programName, '/') + 1;

        do {
            execle(fcgi_suexec, fcgi_suexec, user, group, shortName, NULL, envPtr);
        } while (errno == EINTR);
    } else {
        do {
            execle(programName, programName, NULL, envPtr);
        } while (errno == EINTR);
    }

    failedSysCall = "execle";


FailedSystemCallExit:
    save_errno = errno;
    /*
     * We had to close all files but the FCGI listener socket in order to
     * exec the application.  So if we want to report exec errors (we do!)
     * we must wait until now to open the log file.
     */
    errorLog = FastCgiProcMgrGetErrLog();
    fprintf(errorLog,
            "[%s] mod_fastcgi: %s pid %ld syscall %s failed"
            " before entering app, errno = %s.\n",
            get_time(), programName, (long) getpid(), failedSysCall,
            strerror(save_errno));
    exit(save_errno);
    return(0);          /* avoid an irrelevant compiler warning */
}

void FastCgiProcMgr(void *data)
{
    FastCgiServerInfo *s;
    int i;
    int status, callWaitPid, callDynamicProcs;
    sigset_t sigMask;
    int alarmLeft = 0;
    pool *tp;
    const char *err;

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
    sigdelset(&sigMask, SIGUSR1);
    sigdelset(&sigMask, SIGHUP);

    if ((signal(SIGTERM, FastCgiProcMgrSignalHander) == SIG_ERR) ||
            (signal(SIGCHLD, FastCgiProcMgrSignalHander) == SIG_ERR) ||
            (signal(SIGALRM, FastCgiProcMgrSignalHander) == SIG_ERR) ||
            (signal(SIGUSR2, FastCgiProcMgrSignalHander) == SIG_ERR) ||
            (signal(SIGUSR1, FastCgiProcMgrSignalHander) == SIG_ERR) ||
            (signal(SIGHUP, FastCgiProcMgrSignalHander) == SIG_ERR)) {
        fprintf(errorLog,
                "[%s] mod_fastcgi: signal() failed (exiting): %s\n",
                get_time(), strerror(errno));
        fflush(errorLog);
        exit(1);
    }

    if (fcgi_suexec) {
        fprintf(errorLog,
            "[%s] FastCGI: suEXEC mechanism enabled (wrapper: %s)\n",
            get_time(), fcgi_suexec);
        fflush(errorLog);
    }

    /* Initialize AppClass */
    tp = make_sub_pool(fcgiPool);
    for(s = fastCgiServers; s != NULL; s = s->next) {
        if (s->directive == APP_CLASS_EXTERNAL)
        continue;

        /* Create the socket */
        s->listenFd = psocket(fcgiPool, s->sockAddr->sa_family, SOCK_STREAM, 0);
        if (s->listenFd < 0) {
            ap_log_error(FCGI_LOG_ERR, NULL,
                         "FastCGI: AppClass \"%s\" disabled: psocket() failed: %s",
                         s->execPath, strerror(errno));
            continue;
        }

        /* bind() and listen() */
        err = sock_bindAndListen(tp, s->sockAddr, s->sockAddrLen,
                                s->listenQueueDepth, s->listenFd);
        if (err) {
            ap_log_error(FCGI_LOG_ERR, NULL,
                         "FastCGI: AppClass \"%s\" disabled: %s",
                         s->execPath, err);
            pclosesocket(fcgiPool, s->listenFd);
            s->listenFd = -1;
            continue;
        }

        for (i = 0; i < s->numProcesses; i++)
            s->procs[i].state = STATE_NEEDS_STARTING;
    }
    destroy_pool(tp);

    /*
     * Loop until SIGTERM
     */
    for (;;) {
        time_t now;
        int sleepSeconds = min(dynamicKillInterval, dynamicUpdateInterval);
        pid_t childPid;
        int waitStatus;
        int numChildren;

        /*
         * If we came out of sigsuspend() for any reason other than
         * SIGALRM, pick up where we left off.
         */
        if (alarmLeft) {
            sleepSeconds = alarmLeft;
        }

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
            if (s->directive == APP_CLASS_EXTERNAL || s->listenFd < 0) {
                continue;
            }
            if(s->directive == APP_CLASS_DYNAMIC) {
                numChildren = dynamicMaxClassProcs;
            } else {
                numChildren = s->numProcesses;
            }
            for(i = 0; i < numChildren; i++) {
                if((s->procs[i].pid <= 0) &&
                    (s->procs[i].state == STATE_NEEDS_STARTING)) {
                    time_t restartTime;
                    time_t now = time(NULL);

                    if (s->procs[i].pid == 0) {
                        restartTime = s->restartTime + s->initStartDelay;
                    } else {
                        restartTime = s->restartTime + s->restartDelay;
                    }

                    if(restartTime <= now) {
                        int restart = (s->procs[i].pid < 0);

                        s->restartTime = now;
                        if(CaughtSigTerm()) {
                            goto ProcessSigTerm;
                        }
                        status = OS_ExecFcgiProgram(
                                &s->procs[i].pid,
                                s->listenFd,
                                s->processPriority,
                                s->execPath,
                                s->envp, s->username, s->group);
                        if(status != 0) {
                            fprintf(errorLog,
                                    "[%s] mod_fastcgi: %s"
                                    " fork failed, errno = %s.\n",
                                    get_time(),
                                    s->execPath,
                                    strerror(errno));
                            fflush(errorLog);
                            /* do not restart failed dynamic apps */
                            if(s->directive != APP_CLASS_DYNAMIC) {
                                sleepSeconds = min(sleepSeconds,
                                        max(s->restartDelay,
                                        FCGI_MIN_EXEC_RETRY_DELAY));
                            } else {
                                s->procs[i].state = STATE_READY;
                            }
                            ASSERT(s->procs[i].pid < 0);
                            break;
                        }
                        if (s->directive == APP_CLASS_DYNAMIC) {
                            s->numProcesses++;
                            globalNumInstances++;
                        }
                        s->procs[i].state = STATE_STARTED;

                        if (restart)
                            s->numRestarts++;

                        if (fcgi_suexec != NULL) {
		            fprintf(errorLog,
				    "[%s] FastCGI: %s (uid %ld, gid %ld) %sstarted with pid %d\n",
				    get_time(), s->execPath, (long)s->uid,
				    (long)s->gid, restart ? "re" : "", s->procs[i].pid);
			}
		        else {
			    fprintf(errorLog,
                                    "[%s] FastCGI: %s %sstarted with pid %d\n",
				    get_time(), s->execPath, restart ? "re" : "",
                                    s->procs[i].pid);
                        }
                        ASSERT(s->procs[i].pid > 0);
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
            alarmLeft = alarm(0);
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
            RemoveRecords();
            now = time(NULL);
            if(epoch == 0) {
                epoch = now;
            }
            if(((long)(now-epoch)>=dynamicKillInterval) ||
                    ((globalNumInstances+dynamicProcessSlack)>=dynamicMaxProcs)) {
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
                    numChildren = dynamicMaxClassProcs;
                } else {
                    numChildren = s->numProcesses;
                }
                for(i = 0; i < numChildren; i++) {
                    if(s->procs[i].pid == childPid) {
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
            s->procs[i].pid = -1;

            /* restart static apps */
            if(s->directive == APP_CLASS_STANDARD) {
                s->procs[i].state = STATE_NEEDS_STARTING;
                s->numFailures++;
            } else {
                s->numProcesses--;
                globalNumInstances--;
                if(s->procs[i].state == STATE_VICTIM) {
                    s->procs[i].state = STATE_KILLED;
                    continue;
                } else {
                    /*
                     * dynamic app shouldn't have died or dynamicAutoUpdate killed it
                     */
                    s->numFailures++;
                    if (dynamicAutoRestart) {
                        s->procs[i].state = STATE_NEEDS_STARTING;
                    } else {
                        s->procs[i].state = STATE_READY;
                    }
                }
            }

            if(WIFEXITED(waitStatus)) {
                fprintf(errorLog,
                        "[%s] mod_fastcgi: %s (pid %d) terminated"
                        " by calling exit with status = %d\n",
                        get_time(), s->execPath, (int)childPid,
                        WEXITSTATUS(waitStatus));
            } else {
                ASSERT(WIFSIGNALED(waitStatus));
                fprintf(errorLog,
                        "[%s] mod_fastcgi: %s (pid %d) terminated"
                        " due to uncaught signal %d\n",
                        get_time(), s->execPath, (int)childPid,
                        WTERMSIG(waitStatus));
            }
            fflush(errorLog);
        } /* for (;;) */
    } /* for (;;) */

ProcessSigTerm:
    /*
     * Kill off the children, then exit.
     */
    while(fastCgiServers != NULL) {
        server_shutdown(fcgiPool, fastCgiServers);
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
#if APACHE_RELEASE < 1030000
int FCGIProcMgrBoot(void *data)
#else
int FCGIProcMgrBoot(void *data, child_info *child_info)
#endif
{
    int n;
    char buf[IOBUFSIZE];

    errorLog = FastCgiProcMgrGetErrLog();

    /*
     * If running as root, reduce privileges.
     */
    if (geteuid() == 0) {
#ifndef __EMX__
        /* OS/2 doesn't support groups. */

        char *name;

        /* Get username if passed as a uid */
        if (user_name[0] == '#') {
            uid_t uid = atoi(&user_name[1]);
            struct passwd *ent = getpwuid(uid);

            if (ent == NULL) {
                fprintf(errorLog, "[%s] mod_fastcgi: "
                    "getpwuid() couldn't determine user name from uid '%u', "
                    "you probably need to modify the User directive, exiting\n",
                     get_time(), (unsigned)uid);
                exit(1);
            }
            name = ent->pw_name;
        }
        else
            name = user_name;

        /* Change Group */
        if (setgid(group_id) == -1) {
            fprintf(errorLog,"[%s] mod_fastcgi: "
                "setgid() failed to set group id to Group '%u', exiting\n",
                get_time(), (unsigned)group_id);
            exit(1);
        }

#ifdef MULTIPLE_GROUPS
        /* Initialize supplementary groups */
        if (initgroups(name, group_id) == -1) {
            fprintf(errorLog,"[%s] mod_fastcgi: "
                "initgroups() failed to set groups for User '%s'"
                "and Group '%u', exiting\n", get_time(), name, (unsigned)group_id);
            exit(1);
        }

/* Based on Apache 1.3.0 main/util.c... */
#elif !defined(QNX) && !defined(MPE) && !defined(BEOS) && !defined(_OSD_POSIX)
/* QNX, MPE and BeOS do not appear to support supplementary groups. */

        if (setgroups(1, &group_id) == -1) {
            fprintf(errorLog,"[%s] mod_fastcgi: "
                "setgroups() failed to set groups to Group[] '%u', exiting\n",
                get_time(), (unsigned)group_id);
            exit(1);
        }
#endif
#endif

        /* Change real, effective, and saved UserId */
        if(setuid(user_id) == -1) {
            fprintf(errorLog, "[%s] mod_fastcgi: "
                "setuid() failed to change to uid '%u', exiting\n",
                get_time(), (unsigned)user_id);
            exit(1);
        }
    }


/*    block_alarms(); */
    if((procMgr=fork())<0) {
        /* error */
        return -1;
    } else if(procMgr==0) {
        /* child */

        /* rename the process for ps - best we can easily */
        strncpy(server_argv0, "fcgiProcMgr", strlen(server_argv0));

        FastCgiProcMgr(data);
    } else {
        /* parent */
/*      unblock_alarms(); */

        /* rename the process for ps - best we can easily */
        strncpy(server_argv0, "fcgiKillMgr", strlen(server_argv0));

        memset(buf, 0, IOBUFSIZE);
        sprintf(buf, "%ld", (long)procMgr);
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
    char buf[IOBUFSIZE];
    int n;
    const char *err;

    /* Register to reset to default values when the config pool is cleaned */
    register_cleanup(p, NULL, conf_reset, null_cleanup);

    conf_setFcgiUidGid(1);

    /*
     * This hack will prevent the starting of the process manager
     * the first time Apache reads its configuration files.
     */
    if (restarts == 0 && standalone == 1) {
        restarts++;
        return;
    }

    /* keep config/perm pool global - its too much of pain to retrofit */
    fcgiPool = p;

    if(s->error_fname != NULL) {
        errorLogPathname = server_root_relative(p, s->error_fname);
    }

    /* Create Unix/Domain socket directory */
    err = conf_createDir(p, ipcDir);
    if (err != NULL) {
        log_printf(s, "FastCGI: %s", err);
    }

    /* Create Dynamic directory and mbox file */
    err = conf_createDynamicDirAndMbox(p);
    if (err != NULL) {
        log_printf(s, "FastCGI: %s", err);
    }

#if APACHE_RELEASE < 1030000
    spawn_child(p, (void *)FCGIProcMgrBoot, NULL,
            kill_always, NULL, &fp);
#else
    /* *** Might want to use a different kill_condition here. */
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

void SignalProcessManager(pool *rp, char id, char *execPath,
              const char *user, const char *group,
              unsigned long qsecs, unsigned long ctime,
              unsigned long now)
{
    AddNewRecord(rp, id, execPath, user, group, qsecs, ctime, now);
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
    u_int bodySize;

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
 *      Queue the environment variables to a FastCGI server.
 *
 * Results:
 *      TRUE if the complete ENV was buffered, FALSE otherwise.
 *
 * Side effects:
 *      Environment variables queued for delivery.
 *      envp is updated to reflect the current position in the ENV.
 *
 *----------------------------------------------------------------------
 */

static int SendEnvironment(request_rec *reqPtr, FastCgiInfo *infoPtr, char ***envp)
{
    static int              headerLen, nameLen, valueLen, totalLen;
    static char             *equalPtr;
    static unsigned char    headerBuff[8];
    static enum SendEnvPassEnum { prep, header, name, value } pass;
    int       charCount;

    /*
     * Send each environment item to the FastCGI server as a
     * FastCGI format name-value pair.
     *
     * XXX: this code will break with the environment format used on NT.
     */
    if (*envp == NULL) {
        add_common_vars(reqPtr);
        add_cgi_vars(reqPtr);
        *envp = create_environment(reqPtr->pool, reqPtr->subprocess_env);
        pass = prep;
    }
    while (**envp) {
        switch (pass) {
            case prep:
                equalPtr = strchr(**envp, '=');
                ASSERT(equalPtr != NULL);
                nameLen = equalPtr - **envp;
                valueLen = strlen(++equalPtr);
                FCGIUtil_BuildNameValueHeader(
                        nameLen,
                        valueLen,
                        headerBuff,
                        &headerLen);
                totalLen = headerLen + nameLen + valueLen;
                pass = header;
                /* drop through */
            case header:
                if (BufferFree(infoPtr->outbufPtr) < (sizeof(FCGI_Header)+headerLen)) {
                    return (FALSE);
                }
                SendPacketHeader(infoPtr, FCGI_PARAMS, totalLen);
                BufferAddData(infoPtr->outbufPtr, (char *)headerBuff, headerLen);
                pass = name;
                /* drop through */
            case name:
                charCount = BufferAddData(infoPtr->outbufPtr, **envp, nameLen);
                if (charCount != nameLen) {
                    **envp += charCount;
                    nameLen -= charCount;
                    return (FALSE);
                }
                pass = value;
                /* drop through */
            case value:
                charCount = BufferAddData(infoPtr->outbufPtr, equalPtr, valueLen);
                if (charCount != valueLen) {
                    equalPtr += charCount;
                    valueLen -= charCount;
                    return (FALSE);
                }
                pass = prep;
        }
        (*envp)++;
    }
    if (BufferFree(infoPtr->outbufPtr) < sizeof(FCGI_Header)) {
        return(FALSE);
    }
    SendPacketHeader(infoPtr, FCGI_PARAMS, 0);
    return(TRUE);
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

static int CgiToClientBuffer(pool *p, FastCgiInfo *infoPtr)
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
            if (header.version != FCGI_VERSION) {
                sprintf(infoPtr->errorMsg,
                        "mod_fastcgi: protocol error: "
                        "invalid header: version(%d) != FCGI_VERSION(%d)",
                        header.version, FCGI_VERSION);
                return SERVER_ERROR;
            }
            if (header.type > FCGI_MAXTYPE) {
                sprintf(infoPtr->errorMsg,
                        "mod_fastcgi: protocol error: "
                        "invalid type: type(%d) > FCGI_MAXTYPE(%d)",
                        header.type, FCGI_MAXTYPE);
                return SERVER_ERROR;
            }

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
                            BufferAppend(p, &infoPtr->header,
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
                    BufferAppend(p, &infoPtr->errorOut,
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
 *      If the end of the string is reached, ASSERT!
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

    ASSERT(*p != '\0');
    end = p;
    end++;

    /*
     * Trim any trailing whitespace.
     */
    while(isspace((unsigned char)p[-1]) && p > start) {
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

void ScanCGIHeader(request_rec *reqPtr, FastCgiInfo *infoPtr)
{
    char *p, *next, *name, *value;
    int len, flag, headerBufLen;
    int hasContentType, hasStatus, hasLocation;

    ASSERT(infoPtr->parseHeader == SCAN_CGI_READING_HEADERS);

    /*
     * Do we have the entire header?  Scan for the blank line that
     * terminates the header.
     */
    p = infoPtr->header;
    len = strlen(infoPtr->header);
    headerBufLen = len;
    flag = 0;
    while(len-- && flag < 2) {
        switch(*p) {
            case '\r':
                break;
            case '\n':
                flag++;
                break;
            case '\0':
            case '\v':
            case '\f':
                name = "Invalid Character";
                goto BadHeader;
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
    next = infoPtr->header;
    for(;;) {
        next = ScanLine(name = next, TRUE);
        if(*name == '\0') {
            break;
        }
        if((p = strchr(name, ':')) == NULL) {
            goto BadHeader;
        }
        value = p + 1;
        while(p != name && isspace((unsigned char)*(p - 1))) {
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
        while(isspace((unsigned char)*value)) {
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
        const char *location = table_get(reqPtr->headers_out, "Location");
        /*
         * Based on internal redirect handling in mod_cgi.c...
         *
         * If a script wants to produce its own Redirect
         * body, it now has to explicitly *say* "Status: 302"
         */
        if (reqPtr->status == 200) {
            if(location[0] == '/') {
                /*
                 * Location is an relative path.  This handler will
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
                infoPtr->parseHeader = SCAN_CGI_SRV_REDIRECT;
                return;
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
    len = headerBufLen - (next - infoPtr->header);
    ASSERT(len >= 0);
    ASSERT(BufferLength(infoPtr->reqOutbufPtr) == 0);
    if(BufferFree(infoPtr->reqOutbufPtr) < len) {
        infoPtr->reqOutbufPtr = BufferCreate(reqPtr->pool, len);
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
    infoPtr->errorMsg = psprintf(reqPtr->pool,
            "mod_fastcgi: Malformed response header from app: '%s'", name);
    goto ErrorReturn;

DuplicateNotAllowed:
    sprintf(infoPtr->errorMsg,
            "mod_fastcgi: Duplicate CGI response header '%s'"
            " not allowed", name);
    goto ErrorReturn;

BadStatusValue:
    infoPtr->errorMsg = psprintf(reqPtr->pool,
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

static void FillOutbuf(request_rec *reqPtr, FastCgiInfo *infoPtr)
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

static void DrainReqOutbuf(request_rec *reqPtr, FastCgiInfo *infoPtr)
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
 * GetUidGid --
 *
 *      Determine the user and group suexec should be called with.
 *      Based on code in Apache's create_argv_cmd() (util_script.c).
 *
 * Results:
 *      0   success
 *      <0  failure
 *
 * Side effects:
 *      none
 *
 *----------------------------------------------------------------------
 */

static void GetUserGroup(request_rec *r, const char **user, const char **group)
{
    if (fcgi_suexec == NULL) {
        *user = "-";
        *group = "-";
        return;
    }

    if (strncmp("/~", r->uri, 2) == 0) {
        /* its a user dir uri, just send the ~user, and leave it to the PM */
        char *end = strchr(r->uri + 2, '/');

        if (end)
            *user = memcpy(pcalloc(r->pool, end - r->uri), r->uri + 1, end - r->uri - 1);
        else
            *user = pstrdup(r->pool, r->uri + 1);
        *group = "-";
    }
    else {
        *user = psprintf(r->pool, "%ld", (long)r->server->server_uid);
        *group = psprintf(r->pool, "%ld", (long)r->server->server_gid);
    }
}

/*
 *----------------------------------------------------------------------
 *
 * ConnectToFcgiApp --
 *
 *      Open a connection to the FastCGI application.
 *
 * Results:
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */
static void CloseConnectionToFcgiApp(FastCgiInfo *infoPtr);

static int ConnectToFcgiApp(request_rec *reqPtr, FastCgiInfo *infoPtr)
{
    int             flags = 0;
    struct timeval  tval;
    fd_set          write_fds, read_fds;
    int             status;
    pool *rp = reqPtr->pool;
    const char *sockPath = NULL;
    struct sockaddr *sockAddr = NULL;
    int sockAddrLen;
    const char *err;

    GetUserGroup(reqPtr, &infoPtr->user, &infoPtr->group);

    /* Create the connection point */
    if (infoPtr->dynamic) {
        sockPath = sock_makeHash(rp, reqPtr->filename, infoPtr->user, infoPtr->group);
        sockPath = sock_makePath(rp, sockPath, 1);
        err = sock_makeDomainAddr(rp, (struct sockaddr_un **)&sockAddr,
                                  &sockAddrLen, sockPath);
        if (err) {
            infoPtr->errorMsg = pstrcat(rp, "mod_fastcgi: ", err, NULL);
            goto Error;
        }
    } else {
        sockAddr = infoPtr->serverPtr->sockAddr;
        sockAddrLen = infoPtr->serverPtr->sockAddrLen;
    }

    /* Dynamic app's lockfile handling */
    if(infoPtr->dynamic) {
        const char *lockFileName = dynamic_makeLockPath(rp, sockPath);
        struct stat  lstbuf;
        struct stat  bstbuf;
        int          result = 0;

        do {
            if( stat(lockFileName,&lstbuf)==0 && S_ISREG(lstbuf.st_mode) ) {
                if (dynamicAutoUpdate &&
                        (stat(reqPtr->filename,&bstbuf) == 0) &&
                        (lstbuf.st_mtime < bstbuf.st_mtime)) {
                    /* Its already running, but there's a newer one,
                     * ask the process manager to start it.
                     * it will notice that the binary is newer,
                     * and do a restart instead.
                     */

                    SignalProcessManager(rp, PLEASE_START,
                        reqPtr->filename, infoPtr->user, infoPtr->group, 0, 0, 0);
                    sleep(1);
                }
                infoPtr->lockFd = popenf(rp, lockFileName, O_APPEND, 0);
                result = (infoPtr->lockFd < 0) ? (0) : (1);
            } else {
                SignalProcessManager(rp, PLEASE_START,
                    reqPtr->filename, infoPtr->user, infoPtr->group, 0, 0, 0);
                sleep(1);
            }
        } while (result != 1);

        /* Block until we get a shared (non-exclusive) read Lock */
        if(ReadwLock(infoPtr->lockFd) < 0) {
            sprintf(infoPtr->errorMsg,
                    "mod_fastcgi: Failed to obtain a shared read lock on lockfile: ");
            goto SystemError;
        }
    }

    /* Create the socket */
    infoPtr->fd = psocket(rp, sockAddr->sa_family, SOCK_STREAM, 0);
    if (infoPtr->fd < 0) {
        sprintf(infoPtr->errorMsg,
                "mod_fastcgi: socket() failed: ");
        goto SystemError;
    }

    if(infoPtr->fd >= FD_SETSIZE) {
        sprintf(infoPtr->errorMsg,
                "mod_fastcgi: socket file descriptor (%u) is larger than "
                "FD_SETSIZE (%u), you probably need to rebuild Apache with a "
                "larger FD_SETSIZE", infoPtr->fd, FD_SETSIZE);
        goto Error;
    }

    /* Connect */
    if ((flags = fcntl(infoPtr->fd, F_GETFL, 0)) < 0) {
        sprintf(infoPtr->errorMsg,
                "mod_fastcgi: fcntl(F_GETFL) failed: ");
        goto SystemError;
    }
    if (fcntl(infoPtr->fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        sprintf(infoPtr->errorMsg,
                "mod_fastcgi: fcntl(F_SETFL) failed: ");
        goto SystemError;
    }
    if (infoPtr->dynamic && (gettimeofday(&(infoPtr->startTime),NULL) < 0)) {
        sprintf(infoPtr->errorMsg,
             "mod_fastcgi: gettimeofday() failed: ");
        goto SystemError;
    }
    if (connect(infoPtr->fd, (struct sockaddr *)sockAddr, sockAddrLen) >= 0) {
        goto ConnectionComplete;
    }
    if (errno != EINPROGRESS) {
        sprintf(infoPtr->errorMsg, "mod_fastcgi: connect() failed: ");
        goto SystemError;
    }

    if (infoPtr->dynamic) {
        do {
            FD_ZERO(&write_fds);
            FD_SET(infoPtr->fd, &write_fds);
            read_fds = write_fds;
            tval.tv_sec = dynamicPleaseStartDelay;
            tval.tv_usec = 0;

#ifdef SELECT_NEEDS_CAST
            status = select((infoPtr->fd+1), (int*)&read_fds, (int*)&write_fds,
                    NULL, &tval);
#else
            status = select((infoPtr->fd+1), &read_fds, &write_fds,
                    NULL, &tval);
#endif
            if(status < 0) {
                break;
            }
            if(gettimeofday(&(infoPtr->queueTime),NULL) < 0) {
                sprintf(infoPtr->errorMsg,
                     "mod_fastcgi: gettimeofday() failed: ");
                goto SystemError;
            }
            if(status == 0) {
                /* select() timed out */
                SignalProcessManager(rp, CONN_TIMEOUT,
                        reqPtr->filename, infoPtr->user, infoPtr->group,
                        (unsigned long)dynamicPleaseStartDelay*1000000,
                        0, 0);
            } else {
                /* connect() completed */
                break;
            }
        } while((infoPtr->queueTime.tv_sec - infoPtr->startTime.tv_sec)
                < dynamicAppConnectTimeout);

        if (status == 0) {
            sprintf(infoPtr->errorMsg,
                "mod_fastcgi: connect() timed out (appConnTimeout=%dsec)",
                dynamicAppConnectTimeout);
            goto Error;
        }
    } else {
        /* its a static app  */
        tval.tv_sec = infoPtr->serverPtr->appConnectTimeout;
        tval.tv_usec = 0;
        FD_ZERO(&write_fds);
        FD_SET(infoPtr->fd, &write_fds);
        read_fds = write_fds;

#ifdef SELECT_NEEDS_CAST
        status = select((infoPtr->fd+1), (int*)&read_fds, (int*)&write_fds,
                NULL, &tval);
#else
        status = select((infoPtr->fd+1), &read_fds, &write_fds,
                NULL, &tval);
#endif
        if (status == 0) {
            sprintf(infoPtr->errorMsg,
                "mod_fastcgi: connect() timed out (appConnTimeout=%dsec)",
                infoPtr->serverPtr->appConnectTimeout);
            goto Error;
        }
    }  /* if (dynamic) else */

    if (status < 0) {
        sprintf(infoPtr->errorMsg, "mod_fastcgi: select() failed: ");
        goto SystemError;
    }

    if (FD_ISSET(infoPtr->fd, &write_fds) || FD_ISSET(infoPtr->fd, &read_fds)) {
        int error = 0;
        int len = sizeof(error);
        if (getsockopt(infoPtr->fd, SOL_SOCKET, SO_ERROR, (char *)&error, &len) < 0) {
            /* Solaris pending error */
            sprintf(infoPtr->errorMsg, "mod_fastcgi: select() failed (Solaris pending error): ");
            goto SystemError;
        }
        if (error != 0) {
            /* Berkeley-derived pending error */
            sprintf(infoPtr->errorMsg, "mod_fastcgi: select() failed (pending error): ");
            errno = error;
            goto SystemError;
        }
    } else {
        sprintf(infoPtr->errorMsg, "mod_fastcgi: select() error - THIS SHOULDN'T HAPPEN!");
        goto Error;
    }

ConnectionComplete:
    if ((fcntl(infoPtr->fd, F_SETFL, flags)) < 0) {
        sprintf(infoPtr->errorMsg,
                "mod_fastcgi: fcntl(F_SETFL) failed: ");
        goto SystemError;
    }
    if (infoPtr->dynamic) {
        if (gettimeofday(&(infoPtr->queueTime),NULL) < 0) {
            sprintf(infoPtr->errorMsg,
                 "mod_fastcgi: gettimeofday() failed: ");
            goto SystemError;
        }
    }

    return TRUE;

SystemError:
    { char* msg = strerror(errno);
      if (msg == NULL) {
          msg = "errno out of range";
      }
      infoPtr->errorMsg = pstrcat(rp, infoPtr->errorMsg, msg, NULL);
    }
Error:
    CloseConnectionToFcgiApp(infoPtr);
    log_reason(infoPtr->errorMsg, reqPtr->filename, reqPtr);
    return FALSE;
}

/*
 *----------------------------------------------------------------------
 *
 * CloseConnectionToFcgiApp --
 *
 *      Closes the connection to the FastCGI application.
 *      Called only by FcgiDoWork() once the comm is complete with the
 *      Fcgi application.
 *
 * Results:
 *
 * Side effects:
 *
 *----------------------------------------------------------------------
 */
static void CloseConnectionToFcgiApp(FastCgiInfo *infoPtr)
{
    pool *rp = infoPtr->reqPtr->pool;

    if (infoPtr->fd != -1)
        pclosesocket(rp, infoPtr->fd);

    if (infoPtr->dynamic) {   /* dynamic == TRUE */
        pclosef(rp, infoPtr->lockFd);

        if(infoPtr->keepReadingFromFcgiApp == FALSE) {
            /* XXX REQ_COMPLETE is only sent for requests which complete
             * normally WRT the fcgi app.  There is no data sent for
             * connect() timeouts or requests which complete abnormally.
             * KillDynamicProcs() and RemoveRecords() need to be looked at
             * to be sure they can reasonably handle these cases before
             * sending these sort of stats - theres some funk in there.
             */
            if(gettimeofday(&(infoPtr->completeTime), NULL) < 0) {
                /* there's no point to aborting the request, just log it */
                fprintf (infoPtr->reqPtr->server->error_log,
                     "mod_fastcgi: gettimeofday() failed: %s\n", strerror(errno));
                fflush (infoPtr->reqPtr->server->error_log);
            } else {
                SignalProcessManager(rp, REQ_COMPLETE, infoPtr->reqPtr->filename,
                    infoPtr->user, infoPtr->group,
                    (unsigned long)((infoPtr->queueTime.tv_sec
                        - infoPtr->startTime.tv_sec)*1000000
                        + infoPtr->queueTime.tv_usec
                        - infoPtr->startTime.tv_usec),
                    (unsigned long)((infoPtr->completeTime.tv_sec
                        - infoPtr->queueTime.tv_sec)*1000000
                        + infoPtr->completeTime.tv_usec
                        - infoPtr->queueTime.tv_usec),
                    (unsigned long)infoPtr->completeTime.tv_sec);
            }
        }
    }
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

static int FastCgiDoWork(request_rec *reqPtr, FastCgiInfo *infoPtr)
{
    struct timeval  timeOut, *timeOutPtr;
    fd_set  read_set, write_set;
    int     status;
    int     numFDs;
    int     doClientWrite;
    int     envSent = FALSE;    /* has the complete ENV been buffered? */
    char    **envp = NULL;      /* pointer used by SendEnvironment() */
    pool *rp = reqPtr->pool;

    FD_ZERO(&read_set);
    FD_ZERO(&write_set);

    SendBeginRequest(infoPtr);

    /* Buffer as much of the environment as we can fit */
    envSent = SendEnvironment(reqPtr, infoPtr, &envp);

    /* Start the Apache dropdead timer.  See http_main.h.
     * ***This needs some attention, reset_timeout() should also
     * be called somewhere below */
    soft_timeout("read script input or send script output", reqPtr);

    /* Read as much as possible from the client. */
    FillOutbuf(reqPtr, infoPtr);

    /* Connect to the Fast CGI Application */
    if (!ConnectToFcgiApp(reqPtr, infoPtr)) {
        goto ConnectError;
    }
    numFDs = infoPtr->fd + 1;

    while(infoPtr->keepReadingFromFcgiApp
            || BufferLength(infoPtr->inbufPtr) > 0
            || BufferLength(infoPtr->reqOutbufPtr) > 0) {

        /* If we didn't buffer all of the environment yet, buffer some more */
        if (!envSent) {
            envSent = SendEnvironment(reqPtr, infoPtr, &envp);
        }
        /* Read as much as possible from the client. */
        if(!infoPtr->eofSent && envSent) {
            FillOutbuf(reqPtr, infoPtr);
        }

        /*
         * To avoid deadlock, don't do a blocking select to write to
         * the FastCGI application without selecting to read from the
         * FastCGI application.
         */
        doClientWrite = FALSE;
        if (infoPtr->keepReadingFromFcgiApp && BufferFree(infoPtr->inbufPtr) > 0) {

            FD_SET(infoPtr->fd, &read_set);

            /* Is data buffered for output to the fcgi app? */
            if (BufferLength(infoPtr->outbufPtr) > 0) {
                FD_SET(infoPtr->fd, &write_set);
            } else {
                FD_CLR(infoPtr->fd, &write_set);
            }
            /*
             * If there's data buffered to send to the client, don't
             * wait indefinitely for the FastCGI app; the app might
             * be doing server push.
             */
            if(BufferLength(infoPtr->reqOutbufPtr) > 0) {
             /* Reset on each pass, since they might be changed by select() */
                timeOut.tv_sec = 0;
                timeOut.tv_usec = 100000;   /* 0.1 sec */
                timeOutPtr = &timeOut;
            } else {
                /* we've got the apache soft_timeout() alarm set,
                   so select() will fail with EINTR as a drop dead TO,
                   i.e. its OK to set this to null.
                   ***TODO: but if the app hasn't accept()ed w/in
                   appConnTimeout, shouldn't we abort? */
                timeOutPtr = NULL;
            }
#ifdef SELECT_NEEDS_CAST
            status = select(numFDs, (int*)&read_set,
                    (int*)&write_set, NULL, timeOutPtr);
#else
            status = select(numFDs, &read_set, &write_set, NULL, timeOutPtr);
#endif
            if(status < 0) {
                sprintf(infoPtr->errorMsg,
                        "mod_fastcgi: select() failed while communicating with application: ");
                goto SystemError;
            } else if(status == 0) {
                /* select() timed out, go ahead and write to client */
                doClientWrite = TRUE;
            }
            /* Read from the fcgi app */
            if(FD_ISSET(infoPtr->fd, &read_set)) {
                status = BufferRead(infoPtr->inbufPtr, infoPtr->fd);
                if(status < 0) {
                    sprintf(infoPtr->errorMsg,
                            "mod_fastcgi: read() failed while communicating with application: ");
                    goto SystemError;
                } else if(status == 0) {
                    infoPtr->keepReadingFromFcgiApp = FALSE;
                    CloseConnectionToFcgiApp(infoPtr);
                }
            }
            /* Write to the fcgi app */
            if(FD_ISSET(infoPtr->fd, &write_set)) {
                if(BufferWrite(infoPtr->outbufPtr, infoPtr->fd) < 0) {
                    sprintf(infoPtr->errorMsg,
                            "mod_fastcgi: write() failed while communicating with application: ");
                    goto SystemError;
                }
            }
        } else {
            doClientWrite = TRUE;
        }
        if(doClientWrite) {
            /* Move data from client output buffer (reqOutBuf) to the client */
            DrainReqOutbuf(reqPtr, infoPtr);
        }
        /* Move data from the app input buffer (inbufPtr) to client
           output buffer (reqOutBuf) */
        if(CgiToClientBuffer(rp, infoPtr) != OK) {
            /* infoPtr->errorMsg is setup by CgiToClientBuffer() */
           goto Error;
        }
        if(infoPtr->keepReadingFromFcgiApp && infoPtr->exitStatusSet) {
            /* we're done talking to the fcgi app */
            infoPtr->keepReadingFromFcgiApp = FALSE;
            CloseConnectionToFcgiApp(infoPtr);
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
            break;
        case SCAN_CGI_READING_HEADERS:
            sprintf(infoPtr->errorMsg,
                    "mod_fastcgi: Unterminated CGI response headers,"
                    " %d bytes received from app",
                    strlen(infoPtr->header));
            goto Error;
        case SCAN_CGI_BAD_HEADER:
            /* infoPtr->errorMsg is setup by ScanHeader() */
            goto Error;
        case SCAN_CGI_INT_REDIRECT:
        case SCAN_CGI_SRV_REDIRECT:
            /*
             * XXX We really must be soaking all client input
             * and all script output.  See mod_cgi.c.
             * There's other differences we need to pick up here as well!
             * This has to be revisited.
             */
            break;
        default:
            ASSERT(FALSE);
    }
    kill_timeout(reqPtr);
    return(OK);

SystemError:
{   char *msg = strerror(errno);
    if (msg == NULL) {
        msg = "errno out of range";
    }
    infoPtr->errorMsg = pstrcat(rp, infoPtr->errorMsg, msg, NULL);
}
Error:
    CloseConnectionToFcgiApp(infoPtr);

ConnectError:
    return(SERVER_ERROR);
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
    if(strlen(infoPtr->errorOut) > 0) {
        /*
         * Would like to call log_reason here, but log_reason
         * says "access failed" which isn't necessarily so.
         */
        fprintf(infoPtr->reqPtr->server->error_log,
                "[%s] mod_fastcgi: stderr output from %s: '%s'\n",
                get_time(), infoPtr->reqPtr->filename,
                infoPtr->errorOut);
        fflush(infoPtr->reqPtr->server->error_log);
    }
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

/* Stolen from mod_cgi.c..
 * KLUDGE --- for back-combatibility, we don't have to check ExecCGI
 * in ScriptAliased directories, which means we need to know if this
 * request came through ScriptAlias or not... so the Alias module
 * leaves a note for us.
 */

static int is_scriptaliased(request_rec *r)
{
    const char *t = table_get(r->notes, "alias-forced-type");
    return t && (!strcasecmp(t, "cgi-script"));
}


static int FastCgiHandler(request_rec *reqPtr)
{
    FastCgiServerInfo *serverInfoPtr = NULL;
    FastCgiInfo *infoPtr = NULL;
    char *argv0 = NULL;
    struct timeval;
    int status;
    pool *rp = reqPtr->pool;

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

    if(!(allow_options(reqPtr) & OPT_EXECCGI) && !is_scriptaliased(reqPtr)) {
        log_reason("mod_fastcgi: Options ExecCGI is off in this directory",
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

    /* See if there's a static server configured */
    serverInfoPtr = server_getById(reqPtr->filename,
                                         reqPtr->server->server_uid,
                                         reqPtr->server->server_gid);
    if (serverInfoPtr == NULL) {
        /* Nope, its a request for a dynamic FastCGI application */
        if (fcgi_suexec != NULL) {
            if (WS_Access(NULL, &reqPtr->finfo, X_OK,
                          reqPtr->server->server_uid,
                          reqPtr->server->server_gid)) {
                log_reason(psprintf(rp,
                    "FastCGI: script not executable by fcgi_suexec (uid %ld, gid %ld)",
                    (long)reqPtr->server->server_uid, (long)reqPtr->server->server_gid),
                    reqPtr->filename, reqPtr);
                return NOT_FOUND;
            }
        }
        else {
            if (WS_Access(NULL, &reqPtr->finfo, X_OK,
                          fcgi_user_id, fcgi_group_id)) {
                log_reason(psprintf(rp,
                    "FastCGI: script not executable by server (uid %ld, gid %ld)",
                    (long)fcgi_user_id, (long)fcgi_group_id),
                    reqPtr->filename, reqPtr);
                return NOT_FOUND;
            }
        }
    }

    status = setup_client_block(reqPtr, REQUEST_CHUNKED_ERROR);
    if (status != OK) {
        return status;
    }

    /*
     * Allocate and initialize FastCGI private data to augment the request
     * structure.
     */
    infoPtr = (FastCgiInfo *)pcalloc(rp, sizeof(FastCgiInfo));
    infoPtr->serverPtr = serverInfoPtr;
    infoPtr->inbufPtr = BufferCreate(rp, SERVER_BUFSIZE);
    infoPtr->outbufPtr = BufferCreate(rp, SERVER_BUFSIZE);
    infoPtr->gotHeader = FALSE;
    infoPtr->reqInbufPtr = BufferCreate(rp, SERVER_BUFSIZE);
    infoPtr->reqOutbufPtr = BufferCreate(rp, SERVER_BUFSIZE);
    infoPtr->errorMsg =  pcalloc(rp, FCGI_ERRMSG_LEN);
    infoPtr->parseHeader = SCAN_CGI_READING_HEADERS;
    infoPtr->header = "";
    infoPtr->errorOut = "";
    infoPtr->reqPtr = reqPtr;
    infoPtr->erBufPtr = BufferCreate(rp, sizeof(FCGI_EndRequestBody) + 1);
    infoPtr->readingEndRequestBody = FALSE;
    infoPtr->exitStatus = 0;
    infoPtr->exitStatusSet = FALSE;
    infoPtr->requestId = 1; /* anything but zero is OK here */
    infoPtr->eofSent = FALSE;
    infoPtr->fd = -1;
    infoPtr->expectingClientContent = (should_client_block(reqPtr) != 0);
    infoPtr->keepReadingFromFcgiApp = TRUE;

    if (serverInfoPtr == NULL)
        infoPtr->dynamic = TRUE;
    else
        infoPtr->dynamic = FALSE;

    /* communicate with fcgi app */
    status = FastCgiDoWork(reqPtr, infoPtr);
    if(status != OK) {
        goto ErrorReturn;
    };

    /* Should this be moved to FcgiDoWork()? */

    /* If a script wants to produce its own Redirect body, it now
     * has to explicitly *say* "Status: 302".  If it wants to use
     * Apache redirects say "Status: 200".  See ScanCGIHeader().
     */
    switch(infoPtr->parseHeader) {
        case SCAN_CGI_INT_REDIRECT:

            /* Based mod_cgi.c..
             *
             * XXX There are still differences between the handling in
             * mod_cgi and mod_fastcgi.  This needs to be revisited.
             *
             * This redirect needs to be a GET no matter what the original
             * method was.
             */
            reqPtr->method = "GET";
            reqPtr->method_number = M_GET;

            /* We already read the message body (if any), so don't allow
             * the redirected request to think it has one.  We can ignore
             * Transfer-Encoding, since we used REQUEST_CHUNKED_ERROR.
             */
            table_unset(reqPtr->headers_in, "Content-length");

            internal_redirect_handler(table_get(reqPtr->headers_out,
                    "Location"), reqPtr);
            break;

        case SCAN_CGI_SRV_REDIRECT:

            status = REDIRECT;
            break;
    }
    goto CleanupReturn;

ErrorReturn:
    log_reason(infoPtr->errorMsg, reqPtr->filename, reqPtr);

CleanupReturn:
    FcgiCleanUp(infoPtr);
    return status;
}


command_rec fastcgi_cmds[] = {
    { "AppClass", conf_AppClass, NULL, RSRC_CONF, RAW_ARGS, NULL },
    { "ExternalAppClass", conf_ExternalAppClass, NULL, RSRC_CONF, RAW_ARGS, NULL },
    { "FastCgiIpcDir", conf_FastCgiIpcDir, NULL, RSRC_CONF, TAKE1, NULL },
    { "FastCgiSuexec", conf_FastCgiSuexec, NULL, RSRC_CONF, TAKE1, NULL },
    { "FCGIConfig", conf_FCGIConfig, NULL, RSRC_CONF, RAW_ARGS, NULL },
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
