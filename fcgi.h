/*
 * $Id: fcgi.h,v 1.29 2001/03/05 15:45:16 robs Exp $
 */

#ifndef FCGI_H
#define FCGI_H

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

#if MODULE_MAGIC_NUMBER < 19980806
#error "This version of mod_fastcgi is incompatible with Apache versions 1.3.1 and earlier."
#error "Please upgrade, or try the last Apache 1.2 compatible release, mod_fastcgi 2.0.18 (no DSO support)."
#endif

#ifndef NO_WRITEV
#include <sys/uio.h>
#endif

#ifdef WIN32
#include "multithread.h"
#else
#include <sys/un.h>
#endif

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

#ifdef WIN32
#define READER 0
#define WRITER 1

#define MBOX_EVENT 0   /* mboc is ready to be read */
#define TERM_EVENT 1   /* termination event */
#define WAKE_EVENT 2   /* notification of child Fserver dieing */

/* Reader/Writer lock structure for NT */
typedef struct _FcgiRWLock {
    HANDLE write_lock;
    HANDLE mutex;
    long counter;          /* number of readers */
} FcgiRWLock;

typedef struct _fcgi_pm_job {
    char id;
    char *fs_path;
    char *user;
    char * group;
    unsigned long qsec;
    unsigned long start_time;
    struct _fcgi_pm_job *next;
} fcgi_pm_job;
#endif

/*
 * ServerProcess holds data for each process associated with
 * a class.  It is embedded in fcgi_server below.
 */
typedef struct _FcgiProcessInfo {
#ifdef WIN32
    HANDLE handle;            /* handle of associated process */
#endif
    pid_t pid;                       /* pid of associated process */
    enum {STATE_STARTED,             /* currently running */
          STATE_NEEDS_STARTING,      /* needs to be started by PM */
          STATE_KILL,                /* kill() is needed */
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
    char *fs_path;                  /* pathname of executable */
    array_header *pass_headers;     /* names of headers to pass in the env */
    u_int idle_timeout;             /* fs idle secs allowed before aborting */
    char **envp;                    /* if NOT NULL, this is the env to send
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
    int initStartDelay;             /* min number of seconds to wait between
                                     * starting of AppClass processes at init */
    u_int restartDelay;             /* number of seconds to wait between
                                     * restarts after failure.  Can be zero. */
    int restartOnExit;              /* = TRUE = restart. else terminate/free */
    u_int numRestarts;              /* Total number of restarts */
    u_int numFailures;              /* num restarts due to exit failure */
    struct sockaddr *socket_addr;   /* Socket Address of FCGI app server class */
#ifdef WIN32
    struct sockaddr *dest_addr;     /* for local apps on NT need socket address */
                                    /* bound to localhost */
#endif
    int socket_addr_len;            /* Length of socket */
    enum {APP_CLASS_UNKNOWN,
          APP_CLASS_STANDARD,
          APP_CLASS_EXTERNAL,
          APP_CLASS_DYNAMIC}
         directive;                 /* AppClass or ExternalAppClass */
    const char *socket_path;        /* Name used to create a socket */
    const char *host;               /* Hostname for externally managed
                                     * FastCGI application processes */
    unsigned short port;            /* Port number either for externally
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
#ifdef WIN32
    FcgiRWLock *dynamic_lock;       /* dynamic server lock */
    HANDLE hPipeMutex;
#endif

    struct _FastCgiServerInfo *next;
} fcgi_server;


/*
 * fcgi_request holds the state of a particular FastCGI request.
 */
typedef struct {
#ifdef WIN32
    SOCKET fd;
#else
    int fd;                         /* connection to FastCGI server */
#endif
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
    table *authHeaders;          /* headers received from an auth fs */
    int auth_compat;             /* whether the auth request is spec compat */
    table *saved_subprocess_env; /* subprocess_env before auth handling */
#if defined(SIGPIPE) && MODULE_MAGIC_NUMBER < 19990320
    void (*apache_sigpipe_handler)(int);
#endif
    int expectingClientContent;     /* >0 => more content, <=0 => no more */
    array_header *header;
    char *fs_stderr;
    int fs_stderr_len;
    int parseHeader;                /* TRUE iff parsing response headers */
    request_rec *r;
    int readingEndRequestBody;
    FCGI_EndRequestBody endRequestBody;
    Buffer *erBufPtr;
    int exitStatus;
    int exitStatusSet;
    unsigned int requestId;
    int eofSent;
    int role;                       /* FastCGI Role: Authorizer or Responder */
    int dynamic;                    /* whether or not this is a dynamic app */
    struct timeval startTime;       /* dynamic app's connect() attempt start time */
    struct timeval queueTime;       /* dynamic app's connect() complete time */
    struct timeval completeTime;    /* dynamic app's connection close() time */
#ifdef WIN32
    FcgiRWLock *lockFd;             /* dynamic app's reader/writer lock */
#else
    int lockFd;                     /* dynamic app's lockfile file descriptor */
#endif
    int keepReadingFromFcgiApp;     /* still more to read from fcgi app? */
    const char *user;               /* user used to invoke app (suexec) */
    const char *group;              /* group used to invoke app (suexec) */
#ifdef WIN32
    BOOL using_npipe_io;             /* named pipe io */
#endif
} fcgi_request;

/* Values of parseHeader field */
#define SCAN_CGI_READING_HEADERS 1
#define SCAN_CGI_FINISHED        0
#define SCAN_CGI_BAD_HEADER     -1
#define SCAN_CGI_INT_REDIRECT   -2
#define SCAN_CGI_SRV_REDIRECT   -3

/* Opcodes for Server->ProcMgr communication */
#define PLEASE_START 83        /* 'S' - start */
#define CONN_TIMEOUT 84        /* 'T' - timeout */
#define REQ_COMPLETE 67        /* 'C' - complete */

/* Authorizer types, for auth directives handling */
#define FCGI_AUTH_TYPE_AUTHENTICATOR  0
#define FCGI_AUTH_TYPE_AUTHORIZER     1
#define FCGI_AUTH_TYPE_ACCESS_CHECKER 2

/* Bits for auth_options */
#define FCGI_AUTHORITATIVE 1
#define FCGI_COMPAT 2

typedef struct
{
    const char *authorizer;
    u_char authorizer_options;
    const char *authenticator;
    u_char authenticator_options;
    const char *access_checker;
    u_char access_checker_options;
} fcgi_dir_config;

#define FCGI_OK     0
#define FCGI_FAILED 1

#ifdef WIN32

#define FCGI_LOG_EMERG_ERRNO    __FILE__,__LINE__,APLOG_EMERG     /* system is unusable */
#define FCGI_LOG_ALERT_ERRNO    __FILE__,__LINE__,APLOG_ALERT     /* action must be taken immediately */
#define FCGI_LOG_CRIT_ERRNO     __FILE__,__LINE__,APLOG_CRIT      /* critical conditions */
#define FCGI_LOG_ERR_ERRNO      __FILE__,__LINE__,APLOG_ERR       /* error conditions */
#define FCGI_LOG_WARN_ERRNO     __FILE__,__LINE__,APLOG_WARNING   /* warning conditions */
#define FCGI_LOG_NOTICE_ERRNO   __FILE__,__LINE__,APLOG_NOTICE    /* normal but significant condition */
#define FCGI_LOG_INFO_ERRNO     __FILE__,__LINE__,APLOG_INFO      /* informational */
#define FCGI_LOG_DEBUG_ERRNO    __FILE__,__LINE__,APLOG_DEBUG     /* debug-level messages */

#define FCGI_LOG_EMERG          __FILE__,__LINE__,APLOG_EMERG|APLOG_WIN32ERROR
#define FCGI_LOG_ALERT          __FILE__,__LINE__,APLOG_ALERT|APLOG_WIN32ERROR
#define FCGI_LOG_CRIT           __FILE__,__LINE__,APLOG_CRIT|APLOG_WIN32ERROR
#define FCGI_LOG_ERR            __FILE__,__LINE__,APLOG_ERR|APLOG_WIN32ERROR
#define FCGI_LOG_WARN           __FILE__,__LINE__,APLOG_WARNING|APLOG_WIN32ERROR
#define FCGI_LOG_NOTICE         __FILE__,__LINE__,APLOG_NOTICE|APLOG_WIN32ERROR
#define FCGI_LOG_INFO           __FILE__,__LINE__,APLOG_INFO|APLOG_WIN32ERROR
#define FCGI_LOG_DEBUG          __FILE__,__LINE__,APLOG_DEBUG|APLOG_WIN32ERROR

#else

#define FCGI_LOG_EMERG    __FILE__,__LINE__,APLOG_EMERG     /* system is unusable */
#define FCGI_LOG_ALERT    __FILE__,__LINE__,APLOG_ALERT     /* action must be taken immediately */
#define FCGI_LOG_CRIT     __FILE__,__LINE__,APLOG_CRIT      /* critical conditions */
#define FCGI_LOG_ERR      __FILE__,__LINE__,APLOG_ERR       /* error conditions */
#define FCGI_LOG_WARN     __FILE__,__LINE__,APLOG_WARNING   /* warning conditions */
#define FCGI_LOG_NOTICE   __FILE__,__LINE__,APLOG_NOTICE    /* normal but significant condition */
#define FCGI_LOG_INFO     __FILE__,__LINE__,APLOG_INFO      /* informational */
#define FCGI_LOG_DEBUG    __FILE__,__LINE__,APLOG_DEBUG     /* debug-level messages */

#define FCGI_LOG_EMERG_ERRNO    FCGI_LOG_EMERG
#define FCGI_LOG_ALERT_ERRNO    FCGI_LOG_ALERT
#define FCGI_LOG_CRIT_ERRNO     FCGI_LOG_CRIT
#define FCGI_LOG_ERR_ERRNO      FCGI_LOG_ERR
#define FCGI_LOG_WARN_ERRNO     FCGI_LOG_WARN
#define FCGI_LOG_NOTICE_ERRNO   FCGI_LOG_NOTICE
#define FCGI_LOG_INFO_ERRNO     FCGI_LOG_INFO
#define FCGI_LOG_DEBUG_ERRNO    FCGI_LOG_DEBUG

#endif

#define FCGI_LOG_EMERG_NOERRNO    __FILE__,__LINE__,APLOG_EMERG|APLOG_NOERRNO
#define FCGI_LOG_ALERT_NOERRNO    __FILE__,__LINE__,APLOG_ALERT|APLOG_NOERRNO
#define FCGI_LOG_CRIT_NOERRNO     __FILE__,__LINE__,APLOG_CRIT|APLOG_NOERRNO
#define FCGI_LOG_ERR_NOERRNO      __FILE__,__LINE__,APLOG_ERR|APLOG_NOERRNO
#define FCGI_LOG_WARN_NOERRNO     __FILE__,__LINE__,APLOG_WARNING|APLOG_NOERRNO
#define FCGI_LOG_NOTICE_NOERRNO   __FILE__,__LINE__,APLOG_NOTICE|APLOG_NOERRNO
#define FCGI_LOG_INFO_NOERRNO     __FILE__,__LINE__,APLOG_INFO|APLOG_NOERRNO
#define FCGI_LOG_DEBUG_NOERRNO    __FILE__,__LINE__,APLOG_DEBUG|APLOG_NOERRNO

#ifdef FCGI_DEBUG
#define FCGIDBG1(a)              ap_log_error(FCGI_LOG_DEBUG,fcgi_apache_main_server,a);
#define FCGIDBG2(a,b)            ap_log_error(FCGI_LOG_DEBUG,fcgi_apache_main_server,a,b);
#define FCGIDBG3(a,b,c)          ap_log_error(FCGI_LOG_DEBUG,fcgi_apache_main_server,a,b,c);
#define FCGIDBG4(a,b,c,d)        ap_log_error(FCGI_LOG_DEBUG,fcgi_apache_main_server,a,b,c,d);
#define FCGIDBG5(a,b,c,d,e)      ap_log_error(FCGI_LOG_DEBUG,fcgi_apache_main_server,a,b,c,d,e);
#define FCGIDBG6(a,b,c,d,e,f)    ap_log_error(FCGI_LOG_DEBUG,fcgi_apache_main_server,a,b,c,d,e,f);
#define FCGIDBG7(a,b,c,d,e,f,g)  ap_log_error(FCGI_LOG_DEBUG,fcgi_apache_main_server,a,b,c,d,e,f,g);
#else
#define FCGIDBG1(a)
#define FCGIDBG2(a,b)
#define FCGIDBG3(a,b,c)
#define FCGIDBG4(a,b,c,d)
#define FCGIDBG5(a,b,c,d,e)
#define FCGIDBG6(a,b,c,d,e,f)
#define FCGIDBG7(a,b,c,d,e,f,g)
#endif

/*
 * Holds the status of the sending of the environment.
 * A quick hack to dump the static vars for the NT port.
 */
typedef struct {
    enum { PREP, HEADER, NAME, VALUE } pass;
    char **envp; 
    int headerLen, nameLen, valueLen, totalLen;
    char *equalPtr;
    unsigned char headerBuff[8];
} env_status;

/*
 * fcgi_config.c
 */
void *fcgi_config_create_dir_config(pool *p, char *dummy);
const char *fcgi_config_make_dir(pool *tp, char *path);
const char *fcgi_config_make_dynamic_dir(pool *p, const int wax);
const char *fcgi_config_new_static_server(cmd_parms *cmd, void *dummy, const char *arg);
const char *fcgi_config_new_external_server(cmd_parms *cmd, void *dummy, const char *arg);
const char *fcgi_config_set_config(cmd_parms *cmd, void *dummy, const char *arg);
const char *fcgi_config_set_fcgi_uid_n_gid(int set);
const char *fcgi_config_new_auth_server(cmd_parms * const cmd,
    fcgi_dir_config *dir_config, const char *fs_path, const char * const compat);
const char *fcgi_config_set_authoritative_slot(const cmd_parms * const cmd,
    fcgi_dir_config * const dir_config, int arg);
const char *fcgi_config_set_socket_dir(cmd_parms *cmd, void *dummy, char *arg);
const char *fcgi_config_set_wrapper(cmd_parms *cmd, void *dummy, const char *arg);
void fcgi_config_reset_globals(void* dummy);
const char *fcgi_config_set_env_var(pool *p, char **envp, unsigned int *envc, char * var);

/*
 * fcgi_pm.c
 */
#ifdef WIN32
void fcgi_pm_main(void *dummy);
#else
int fcgi_pm_main(void *dummy, child_info *info);
#endif

/*
 * fcgi_protocol.c
 */
void fcgi_protocol_queue_begin_request(fcgi_request *fr);
void fcgi_protocol_queue_client_buffer(fcgi_request *fr);
int fcgi_protocol_queue_env(request_rec *r, fcgi_request *fr, env_status *env);
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

#ifdef WIN32
int fcgi_buf_add_fd(Buffer *buf, SOCKET fd);
int fcgi_buf_get_to_fd(Buffer *bufPtr, SOCKET fd);
#else
int fcgi_buf_add_fd(Buffer *buf, int fd);
int fcgi_buf_get_to_fd(Buffer *bufPtr, int fd);
#endif

void fcgi_buf_get_block_info(Buffer *bufPtr, char **beginPtr, size_t *countPtr);
void fcgi_buf_toss(Buffer *bufPtr, size_t count);
void fcgi_buf_get_free_block_info(Buffer *bufPtr, char **endPtr, size_t *countPtr);
void fcgi_buf_add_update(Buffer *bufPtr, size_t count);
int fcgi_buf_add_block(Buffer *bufPtr, char *data, size_t datalen);
int fcgi_buf_add_string(Buffer *bufPtr, char *str);
int fcgi_buf_get_to_block(Buffer *bufPtr, char *data, int datalen);
void fcgi_buf_get_to_buf(Buffer *toPtr, Buffer *fromPtr, int len);
void fcgi_buf_get_to_array(Buffer *buf,array_header *arr, size_t len);

/*
 * fcgi_util.c
 */

/* Set a shared read lock, wait until you have it.  */
#ifdef WIN32
#define fcgi_wait_for_shared_read_lock(fd) fcgi_rdwr_lock(fd, READER)
#else
#define fcgi_wait_for_shared_read_lock(fd) fcgi_util_lock_fd((fd), F_SETLKW, F_RDLCK, 0, SEEK_SET, 0)
#endif

/* Set an exclusive write lock, no wait, failure->errno==EACCES.  */
#ifdef WIN32
#define fcgi_get_exclusive_write_lock_no_wait(fd) fcgi_rdwr_try_lock(fd, WRITER)
#else
#define fcgi_get_exclusive_write_lock_no_wait(fd) fcgi_util_lock_fd(fd, F_SETLK, F_WRLCK, 0, SEEK_SET, 0)
#endif

/* Set a shared write lock, wait until you have it.  */
#ifdef WIN32
#define fcgi_wait_for_shared_write_lock(fd) fcgi_rdwr_lock(fd, WRITER)
#else
#define fcgi_wait_for_shared_write_lock(fd) fcgi_util_lock_fd(fd, F_SETLKW, F_WRLCK, 0, SEEK_SET, 0)
#endif

char *fcgi_util_socket_hash_filename(pool *p, const char *path,
    const char *user, const char *group);
const char *fcgi_util_socket_make_path_absolute(pool * const p,
    const char *const file, const int dynamic);
const char *fcgi_util_socket_get_lock_filename(pool *p, const char *socket_path);
#ifndef WIN32
const char *fcgi_util_socket_make_domain_addr(pool *p, struct sockaddr_un **socket_addr,
    int *socket_addr_len, const char *socket_path);
#endif
const char *fcgi_util_socket_make_inet_addr(pool *p, struct sockaddr_in **socket_addr,
    int *socket_addr_len, const char *host, unsigned short port);
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

int fcgi_util_gettimeofday(struct timeval *);

#ifdef WIN32
FcgiRWLock * fcgi_rdwr_create(void);
void fcgi_rdwr_destroy(FcgiRWLock *);
int fcgi_rdwr_lock(FcgiRWLock *, int);
int fcgi_rdwr_try_lock(FcgiRWLock *, int);
int fcgi_rdwr_unlock(FcgiRWLock *, int);

int fcgi_pm_add_job(fcgi_pm_job *new_job);
#endif


/*
 * Globals
 */

extern pool *fcgi_config_pool;

extern server_rec *fcgi_apache_main_server;

extern const char *fcgi_wrapper;                 /* wrapper path */
extern uid_t fcgi_user_id;                       /* the run uid of Apache & PM */
extern gid_t fcgi_group_id;                      /* the run gid of Apache & PM */

extern fcgi_server *fcgi_servers;

extern char *fcgi_socket_dir;             /* default FastCgiIpcDir */

/* pipe used for comm between the request handlers and the PM */
extern int fcgi_pm_pipe[];

extern pid_t fcgi_pm_pid;

extern char *fcgi_dynamic_dir;            /* directory for the dynamic
                                           * fastcgi apps' sockets */

extern char *fcgi_empty_env;

extern int fcgi_dynamic_total_proc_count;
extern time_t fcgi_dynamic_epoch;
extern time_t fcgi_dynamic_last_analyzed;

#ifdef WIN32
extern HANDLE *fcgi_dynamic_mbox_mutex;
extern HANDLE fcgi_event_handles[3];
extern fcgi_pm_job *fcgi_dynamic_mbox;
#endif

extern u_int dynamicMaxProcs;
extern u_int dynamicMinProcs;
extern u_int dynamicMaxClassProcs;
extern u_int dynamicKillInterval;
extern u_int dynamicUpdateInterval;
extern float dynamicGain;
extern u_int dynamicThreshold1;
extern u_int dynamicThresholdN;
extern u_int dynamicPleaseStartDelay;
extern u_int dynamicAppConnectTimeout;
extern char **dynamicEnvp;
extern u_int dynamicProcessSlack;
extern int dynamicAutoRestart;
extern int dynamicAutoUpdate;
extern u_int dynamicListenQueueDepth;
extern u_int dynamicInitStartDelay;
extern u_int dynamicRestartDelay;
extern array_header *dynamic_pass_headers;
extern u_int dynamic_idle_timeout;

extern module MODULE_VAR_EXPORT fastcgi_module;

#endif  /* FCGI_H */

