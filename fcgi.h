/* 
 * $Id: fcgi.h,v 1.2 1999/02/10 03:10:42 roberts Exp $
 */

#ifndef FCGI_H
#define FCGI_H

/* @@@ This is a bit sloppy, but for now.. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#ifndef NO_WRITEV
#include <sys/uio.h>
#endif
#include <sys/un.h>
#include <unistd.h>

/* Apache header files */
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

/* FastCGI header files */
#include "mod_fastcgi.h"
/* @@@ This should go away when fcgi_protocol is re-written */
#include "fcgi_protocol.h"

typedef struct {
    int size;               /* size of entire buffer */
    int length;             /* number of bytes in current buffer */
    char *begin;            /* begining of valid data */
    char *end;              /* end of valid data */
    char data[1];           /* buffer data */
} Buffer;

/*
 * ServerProcess holds data for each process associated with
 * a class.  It is embedded in fcgi_server below.
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
 * fcgi_server holds info for each AppClass specified in this
 * Web server's configuration.
 */
typedef struct _FastCgiServerInfo {
	int flush;
    const char *fs_path;            /* pathname of executable */
    const char **envp;              /* if NOT NULL, this is the env to send
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
    struct sockaddr *socket_addr;      /* Socket Address of FCGI app server class */
    int socket_addr_len;                /* Length of socket */
    enum {APP_CLASS_UNKNOWN,
          APP_CLASS_STANDARD,
          APP_CLASS_EXTERNAL,
          APP_CLASS_DYNAMIC}
         directive;                 /* AppClass or ExternalAppClass */
    const char *socket_path;           /* Name used to create a socket */
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
} fcgi_server;


/*
 * fcgi_request holds the state of a particular FastCGI request.
 */
typedef struct {
    int fd;                         /* connection to FastCGI server */
    int gotHeader;                  /* TRUE if reading content bytes */
    unsigned char packetType;       /* type of packet */
    int dataLen;                    /* length of data bytes */
    int paddingLen;                 /* record padding after content */
    fcgi_server *fs;                /* FastCGI server info */
    const char *fs_path;         /* fcgi_server path */
    Buffer *serverInputBuffer;   /* input buffer from FastCgi server */
    Buffer *serverOutputBuffer;  /* output buffer to FastCgi server */
    Buffer *clientInputBuffer;   /* client input buffer */
    Buffer *clientOutputBuffer;  /* client output buffer */
    table *authHeaders;
    void (*apache_sigpipe_handler)(int);
    int expectingClientContent;     /* >0 => more content, <=0 => no more */
    array_header *header;
    char *fs_stderr;
    int parseHeader;                /* TRUE iff parsing response headers */
    request_rec *r;
    int readingEndRequestBody;
    FCGI_EndRequestBody endRequestBody;
    Buffer *erBufPtr;
    int exitStatus;
    int exitStatusSet;
    int requestId;
    int eofSent;
    int role;                       /* FastCGI Role: Authorizer or Responder */
    int dynamic;                    /* whether or not this is a dynamic app */
    struct timeval startTime;       /* dynamic app's connect() attempt start time */
    struct timeval queueTime;       /* dynamic app's connect() complete time */
    struct timeval completeTime;    /* dynamic app's connection close() time */
    int lockFd;                     /* dynamic app's lockfile file descriptor */
    int keepReadingFromFcgiApp;     /* still more to read from fcgi app? */
    const char *user;               /* user used to invoke app (suexec) */
    const char *group;              /* group used to invoke app (suexec) */
} fcgi_request;

/* Values of parseHeader field */
#define SCAN_CGI_READING_HEADERS 1
#define SCAN_CGI_FINISHED        0
#define SCAN_CGI_BAD_HEADER     -1
#define SCAN_CGI_INT_REDIRECT   -2
#define SCAN_CGI_SRV_REDIRECT   -3

/* Opcodes for Server->ProcMgr communication */
#define PLEASE_START 49        /* start dynamic application */
#define CONN_TIMEOUT 50        /* start another copy of application */
#define REQ_COMPLETE 51        /* do some data analysis */

typedef struct
{
	const char *authorizer;
	int authorizer_authoritative;
	const char *authenticator;
	int authenticator_authoritative;
	const char *access_checker;
	int access_checker_authoritative;
} fcgi_dir_config;

#define	FCGI_LOG_EMERG    __FILE__,__LINE__,APLOG_EMERG		/* system is unusable */
#define	FCGI_LOG_ALERT    __FILE__,__LINE__,APLOG_ALERT		/* action must be taken immediately */
#define	FCGI_LOG_CRIT     __FILE__,__LINE__,APLOG_CRIT		/* critical conditions */
#define	FCGI_LOG_ERR      __FILE__,__LINE__,APLOG_ERR		/* error conditions */
#define	FCGI_LOG_WARNING  __FILE__,__LINE__,APLOG_WARNING	/* warning conditions */
#define	FCGI_LOG_NOTICE   __FILE__,__LINE__,APLOG_NOTICE	/* normal but significant condition */
#define	FCGI_LOG_INFO     __FILE__,__LINE__,APLOG_INFO		/* informational */
#define	FCGI_LOG_DEBUG    __FILE__,__LINE__,APLOG_DEBUG		/* debug-level messages */

#define	FCGI_LOG_EMERG_NOERRNO    __FILE__,__LINE__,APLOG_EMERG|APLOG_NOERRNO
#define	FCGI_LOG_ALERT_NOERRNO    __FILE__,__LINE__,APLOG_ALERT|APLOG_NOERRNO
#define	FCGI_LOG_CRIT_NOERRNO     __FILE__,__LINE__,APLOG_CRIT|APLOG_NOERRNO
#define	FCGI_LOG_ERR_NOERRNO      __FILE__,__LINE__,APLOG_ERR|APLOG_NOERRNO
#define	FCGI_LOG_WARNING_NOERRNO  __FILE__,__LINE__,APLOG_WARNING|APLOG_NOERRNO
#define	FCGI_LOG_NOTICE_NOERRNO   __FILE__,__LINE__,APLOG_NOTICE|APLOG_NOERRNO
#define	FCGI_LOG_INFO_NOERRNO     __FILE__,__LINE__,APLOG_INFO|APLOG_NOERRNO
#define	FCGI_LOG_DEBUG_NOERRNO    __FILE__,__LINE__,APLOG_DEBUG|APLOG_NOERRNO

#ifdef FCGI_DEBUG
#define FCGIDBG1(a)          ap_log_error(FCGI_LOG_DEBUG,NULL,a);
#define FCGIDBG2(a,b)        ap_log_error(FCGI_LOG_DEBUG,NULL,a,b);
#define FCGIDBG3(a,b,c)      ap_log_error(FCGI_LOG_DEBUG,NULL,a,b,c);
#define FCGIDBG4(a,b,c,d)    ap_log_error(FCGI_LOG_DEBUG,NULL,a,b,c,d);
#define FCGIDBG5(a,b,c,d,e)  ap_log_error(FCGI_LOG_DEBUG,NULL,a,b,c,d,e);
#else
#define FCGIDBG1(a)
#define FCGIDBG2(a,b)
#define FCGIDBG3(a,b,c)
#define FCGIDBG4(a,b,c,d)
#define FCGIDBG5(a,b,c,d,e)
#endif 

/* 
 * fcgi_config.c
 */
void *fcgi_config_create_dir_config(pool *p, char *dummy);
const char *fcgi_config_make_dir(pool *tp, char *path);
const char *fcgi_config_make_dynamic_dir_n_mbox(pool *p);
const char *fcgi_config_new_static_server(cmd_parms *cmd, void *dummy, const char *arg);
const char *fcgi_config_new_external_server(cmd_parms *cmd, void *dummy, const char *arg);
const char *fcgi_config_set_config(cmd_parms *cmd, void *dummy, const char *arg);
const char *fcgi_config_set_fcgi_uid_n_gid(int set);
const char *fcgi_config_set_fs_path_slot(cmd_parms *cmd, char *mconfig, char *f);
const char *fcgi_config_set_socket_dir(cmd_parms *cmd, void *dummy, char *arg);
const char *fcgi_config_set_suexec(cmd_parms *cmd, void *dummy, const char *arg);
void fcgi_config_reset_globals(void* dummy);

/*
 * fcgi_pm.c
 */
int fcgi_pm_main(void *dummy, child_info *info);

/*
 * fcgi_protocol.c
 */
void fcgi_protocol_queue_begin_request(fcgi_request *fr);
void fcgi_protocol_queue_client_buffer(fcgi_request *fr);
int fcgi_protocol_queue_env(request_rec *r, fcgi_request *fr, char ***envp);
int fcgi_protocol_dequeue(pool *p, fcgi_request *fr);

/* 
 * fcgi_buf.c 
 */
#define BufferLength(b)     ((b)->length)
#define BufferFree(b)       ((b)->size - (b)->length)
#define BufferSize(b)       ((b)->size)

void fcgi_buf_check(Buffer *bufPtr);
void fcgi_buf_reset(Buffer *bufPtr);
Buffer *fcgi_buf_new(pool *p, int size);
void BufferDelete(Buffer *bufPtr);
int fcgi_buf_add_fd(Buffer *bufPtr, int fd);
int fcgi_buf_get_to_fd(Buffer *bufPtr, int fd);
void fcgi_buf_get_block_info(Buffer *bufPtr, char **beginPtr, int *countPtr);
void fcgi_buf_toss(Buffer *bufPtr, int count);
void fcgi_buf_get_free_block_info(Buffer *bufPtr, char **endPtr, int *countPtr);
void fcgi_buf_add_update(Buffer *bufPtr, int count);
int fcgi_buf_add_block(Buffer *bufPtr, char *data, int datalen);
int fcgi_buf_add_string(Buffer *bufPtr, char *str);
int fcgi_buf_get_to_block(Buffer *bufPtr, char *data, int datalen);
void fcgi_buf_get_to_buf(Buffer *toPtr, Buffer *fromPtr, int len);
void fcgi_buf_get_to_array(Buffer *buf,array_header *arr, int len);

/*
 * fcgi_util.c
 */

/* Set a shared read lock, wait until you have it.  */
#define fcgi_wait_for_shared_read_lock(fd) fcgi_util_lock_fd((fd), F_SETLKW, F_RDLCK, 0, SEEK_SET, 0)

/* Set an exclusive write lock, no wait, failure->errno==EACCES.  */
#define fcgi_get_exclusive_write_lock_no_wait(fd) fcgi_util_lock_fd(fd, F_SETLK, F_WRLCK, 0, SEEK_SET, 0)

/* Set a shared write lock, wait until you have it.  */
#define fcgi_wait_for_shared_write_lock(fd) fcgi_util_lock_fd(fd, F_SETLKW, F_WRLCK, 0, SEEK_SET, 0)

/* Remove a shared or exclusive lock, no wait, failure->errno=EACCES.  */
#define fcgi_unlock(fd) fcgi_util_lock_fd(fd, F_SETLK, F_UNLCK, 0, SEEK_SET, 0)

char *fcgi_util_socket_hash_filename(pool *p, const char *path,
	const char *user, const char *group);
const char *fcgi_util_socket_make_path_absolute(pool * const p, 
  	const char *const file, const int dynamic);
const char *fcgi_util_socket_get_lock_filename(pool *p, const char *socket_path);
const char *fcgi_util_socket_make_domain_addr(pool *p, struct sockaddr_un **socket_addr,
  	int *socket_addr_len, const char *socket_path);
const char *fcgi_util_socket_make_inet_addr(pool *p, struct sockaddr_in **socket_addr,
  	int *socket_addr_len, const char *host, int port);
const char *fcgi_util_check_access(pool *tp, 
    const char * const path, const struct stat *statBuf, 
    const int mode, const uid_t uid, const gid_t gid);
fcgi_server *fcgi_util_fs_get_by_id(const char *ePath, uid_t uid, gid_t gid);
fcgi_server *fcgi_util_fs_get(const char *ePath, const char *user, const char *group);
const char *fcgi_util_fs_is_path_ok(pool * const p, const char * const fs_path, 
	struct stat *finfo, const uid_t uid, const gid_t gid);
fcgi_server *fcgi_util_fs_new(pool *p);
void fcgi_util_fs_add(fcgi_server *s);
const char *fcgi_util_fs_set_uid_n_gid(pool *p, fcgi_server *s, uid_t uid, gid_t gid);
ServerProcess *fcgi_util_fs_create_procs(pool *p, int num);
int fcgi_util_lock_fd(int fd, int cmd, int type, off_t offset, int whence, off_t len);



/*
 * Globals
 */

extern pool *fcgi_config_pool;

extern server_rec *fcgi_apache_parent_server;

extern const char *fcgi_suexec;           /* suexec_bin path */
extern uid_t fcgi_user_id;                       /* the run uid of Apache & PM */
extern gid_t fcgi_group_id;                      /* the run gid of Apache & PM */

extern fcgi_server *fcgi_servers;

extern char *fcgi_socket_dir;             /* default FastCgiIpcDir */

extern pid_t fcgi_pm_pid;

extern char *fcgi_dynamic_dir;            /* directory for the dynamic
                                           * fastcgi apps' sockets */
extern char *fcgi_dynamic_mbox;           /* file through which the fcgi */

extern u_int dynamicMaxProcs;
extern u_int dynamicMinProcs;
extern u_int dynamicMaxClassProcs;
extern u_int dynamicKillInterval;
extern u_int dynamicUpdateInterval;
extern float dynamicGain;
extern u_int dynamicThreshhold1;
extern u_int dynamicThreshholdN;
extern u_int dynamicPleaseStartDelay;
extern u_int dynamicAppConnectTimeout;
extern const char **dynamicEnvp;
extern u_int dynamicProcessSlack;
extern int dynamicAutoRestart;
extern int dynamicAutoUpdate;
extern u_int dynamicListenQueueDepth;
extern u_int dynamicInitStartDelay;
extern u_int dynamicRestartDelay;

extern module fastcgi_module;

#endif	/* FCGI_H */

