/*
 * $Id: mod_fastcgi.h,v 1.10 1999/02/24 04:42:38 roberts Exp $
 */

#ifndef MOD_FASTCGI_H
#define MOD_FASTCGI_H

#define MOD_FASTCGI_VERSION "2.2.1"

#define FCGI_DEFAULT_LISTEN_Q 5            /* listen queue size */
#define FCGI_DEFAULT_RESTART_DELAY 5       /* delay between restarts */
#define DEFAULT_INIT_START_DELAY 1         /* delay between starts */
#define FCGI_DEFAULT_PRIORITY 0            /* process priority - not used */
#define FCGI_ERRMSG_LEN 200                /* size of error buffer */
#define FCGI_MIN_EXEC_RETRY_DELAY 10       /* minimum number of seconds to
                                              wait before restarting */
#define MAX_INIT_ENV_VARS 64               /* max # of -initial-env options */

/* max number of chars of stderr we can handle from a FastCGI Server */
#define FCGI_SERVER_MAX_STDERR_LEN 2047     

#define SERVER_BUFSIZE 8192

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

#define FCGI_MAGIC_TYPE "application/x-httpd-fcgi"

#undef FCGI_DEBUG

#ifndef PATH_MAX
#define PATH_MAX (1024)
#endif

#define MAX_PROCMGR_RECORD_LEN (PATH_MAX)

#ifdef OPEN_MAX
#define MAX_OPEN_FDS OPEN_MAX
#else
#define MAX_OPEN_FDS (128)
#endif

#ifndef SUN_LEN
#define SUN_LEN(sock) \
    (sizeof(*(sock)) - sizeof((sock)->sun_path) + strlen((sock)->sun_path))
#endif

#if defined MAXLOGNAME && MAXLOGNAME > 15
#define MAX_USER_NAME_LEN MAXLOGNAME
#elif defined UT_NAMESIZE && UT_NAMESIZE > 15
#define MAX_USER_NAME_LEN UT_NAMESIZE
#else
#define MAX_USER_NAME_LEN 15     /* Max len of user name (suexec w/ ~user), */
#endif                           /* must accomodate uid printed as %ld too */
#define MAX_GID_CHAR_LEN 15      /* Max #chars in a gid printed as %ld */

#ifndef TRUE
#define TRUE  (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif

/* This is (more or less) from http_main.c. It should be in an Apache header */
#ifndef SYS_SIGLIST
#define SYS_SIGLIST ap_sys_siglist
extern const char *ap_sys_siglist[]; 
#endif

#endif	/* MOD_FASTCGI_H */




