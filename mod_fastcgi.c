/*
 * mod_fastcgi.c --
 *
 *      Apache server module for FastCGI.
 *
 *  $Id: mod_fastcgi.c,v 1.92 2000/05/10 05:15:48 robs Exp $
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
 *   The Apache Timeout directive allows per-server configuration of
 *   the timeout associated with a request.  This is typically used to
 *   detect dead clients.  The timer is reset for every successful
 *   read/write.  The default value is 5min.  Thats way too long to tie
 *   up a FastCGI server.  For now this dropdead timer is used a little
 *   differently in FastCGI.  All of the FastCGI server I/O AND the
 *   client I/O must complete within Timeout seconds.  This isn't
 *   exactly what we want.. it should be revisited.  See http_main.h.
 *
 *   We need a way to configurably control the timeout associated with
 *   FastCGI server exchanges AND one for client exchanges.  This could
 *   be done with the select() in doWork() (which should be rewritten
 *   anyway).  This will allow us to free up the FastCGI as soon as
 *   possible.
 *
 *   Earlier versions of this module used ap_soft_timeout() rather than
 *   ap_hard_timeout() and ate FastCGI server output until it completed.
 *   This precluded the FastCGI server from having to implement a
 *   SIGPIPE handler, but meant hanging the application longer than
 *   necessary.  SIGPIPE handler now must be installed in ALL FastCGI
 *   applications.  The handler should abort further processing and go
 *   back into the accept() loop.
 *
 *   Although using ap_soft_timeout() is better than ap_hard_timeout()
 *   we have to be more careful about SIGINT handling and subsequent
 *   processing, so, for now, make it hard.
 */


#include "fcgi.h"

#ifndef timersub
#define	timersub(a, b, result)                              \
do {                                                        \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;           \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;        \
    if ((result)->tv_usec < 0) {                            \
        --(result)->tv_sec;                                 \
        (result)->tv_usec += 1000000;                       \
    }                                                       \
} while (0)
#endif

/*
 * Global variables
 */

pool *fcgi_config_pool;            	 /* the config pool */
server_rec *fcgi_apache_main_server;

const char *fcgi_suexec = NULL;           /* suexec_bin path */
uid_t fcgi_user_id;                       /* the run uid of Apache & PM */
gid_t fcgi_group_id;                      /* the run gid of Apache & PM */

fcgi_server *fcgi_servers = NULL; 		 /* AppClasses */

char *fcgi_socket_dir = DEFAULT_SOCK_DIR; /* default FastCgiIpcDir */

int fcgi_pm_pipe[2];
pid_t fcgi_pm_pid = -1;

char *fcgi_dynamic_dir = NULL;            /* directory for the dynamic
                                                  * fastcgi apps' sockets */

#ifdef WIN32
fcgi_pm_job *fcgi_dynamic_mbox = NULL;
HANDLE *fcgi_dynamic_mbox_mutex = NULL;
HANDLE fcgi_pm_thread = INVALID_HANDLE_VALUE;
#endif

char *fcgi_empty_env = NULL;

u_int dynamicMaxProcs = FCGI_DEFAULT_MAX_PROCS;
u_int dynamicMinProcs = FCGI_DEFAULT_MIN_PROCS;
u_int dynamicMaxClassProcs = FCGI_DEFAULT_MAX_CLASS_PROCS;
u_int dynamicKillInterval = FCGI_DEFAULT_KILL_INTERVAL;
u_int dynamicUpdateInterval = FCGI_DEFAULT_UPDATE_INTERVAL;
float dynamicGain = FCGI_DEFAULT_GAIN;
u_int dynamicThreshhold1 = FCGI_DEFAULT_THRESHHOLD_1;
u_int dynamicThreshholdN = FCGI_DEFAULT_THRESHHOLD_N;
u_int dynamicPleaseStartDelay = FCGI_DEFAULT_START_PROCESS_DELAY;
u_int dynamicAppConnectTimeout = FCGI_DEFAULT_APP_CONN_TIMEOUT;
char **dynamicEnvp = &fcgi_empty_env;
u_int dynamicProcessSlack = FCGI_DEFAULT_PROCESS_SLACK;
int dynamicAutoRestart = FCGI_DEFAULT_RESTART_DYNAMIC;
int dynamicAutoUpdate = FCGI_DEFAULT_AUTOUPDATE;
u_int dynamicListenQueueDepth = FCGI_DEFAULT_LISTEN_Q;
u_int dynamicInitStartDelay = DEFAULT_INIT_START_DELAY;
u_int dynamicRestartDelay = FCGI_DEFAULT_RESTART_DELAY;
array_header *dynamic_pass_headers = NULL;
u_int dynamic_idle_timeout = FCGI_DEFAULT_IDLE_TIMEOUT;

/*******************************************************************************
 * Construct a message and write it to the pm_pipe.
 */
static void send_to_pm(pool * const p, const char id, const char * const fs_path,
     const char *user, const char * const group, const unsigned long q_usec,
     const unsigned long req_usec)
{
#ifdef WIN32
    fcgi_pm_job *job = NULL;

    if (!(job = (fcgi_pm_job *) malloc(sizeof(fcgi_pm_job))))
       return;
#else
    int buflen = 0;
    char buf[FCGI_MAX_MSG_LEN];
#endif

    if (strlen(fs_path) > FCGI_MAXPATH) {
        ap_log_error(FCGI_LOG_ERR_NOERRNO, fcgi_apache_main_server, 
            "FastCGI: the path \"%s\" is too long (>%d) for a dynamic server", fs_path, FCGI_MAXPATH);
        return;
    }

    switch(id) {
    case PLEASE_START:
#ifdef WIN32
        job->id = id;
        job->fs_path = strdup(fs_path);
        job->user = strdup(user);
        job->group = strdup(group);
#else
        buflen = sprintf(buf, "%c %s %s %s*", id, fs_path, user, group);
#endif
        break;
    case CONN_TIMEOUT:
#ifdef WIN32
        job->id = id;
        job->fs_path = strdup(fs_path);
        job->user = strdup(user);
        job->group = strdup(group);
#else
        buflen = sprintf(buf, "%c %s %s %s*", id, fs_path, user, group);
#endif
        break;
    case REQ_COMPLETE:
#ifdef WIN32
        job->id = id;
        job->fs_path = strdup(fs_path);
        job->qsec = q_usec;
        job->start_time = req_usec;
        job->user = strdup(user);
        job->group = strdup(group);
#else
        buflen = sprintf(buf, "%c %s %s %s %lu %lu*", id, fs_path, user, group, q_usec, req_usec);
#endif
        break;
    }

#ifdef WIN32
    if (fcgi_pm_add_job(job) == 0)
        return;

    SetEvent(fcgi_event_handles[MBOX_EVENT]);
#else
    ap_assert(buflen <= FCGI_MAX_MSG_LEN);

    if (write(fcgi_pm_pipe[1], (const void *)buf, buflen) != buflen) {
	ap_log_error(FCGI_LOG_WARN, fcgi_apache_main_server,
	    "FastCGI: write() to PM failed");
    }
#endif
}


/*
 *----------------------------------------------------------------------
 *
 * init_module
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
static void init_module(server_rec *s, pool *p)
{
    const char *err;

    /* Register to reset to default values when the config pool is cleaned */
    ap_block_alarms();
    ap_register_cleanup(p, NULL, fcgi_config_reset_globals, ap_null_cleanup);
    ap_unblock_alarms();

    ap_add_version_component("mod_fastcgi/" MOD_FASTCGI_VERSION);

    fcgi_config_set_fcgi_uid_n_gid(1);

    /* keep these handy */
    fcgi_config_pool = p;
    fcgi_apache_main_server = s;

#ifndef WIN32
    /* Create Unix/Domain socket directory */
    if ((err = fcgi_config_make_dir(p, fcgi_socket_dir)))
        ap_log_error(FCGI_LOG_ERR, s, "FastCGI: %s", err);
#endif

    /* Create Dynamic directory */
    if ((err = fcgi_config_make_dynamic_dir(p, 1)))
        ap_log_error(FCGI_LOG_ERR, s, "FastCGI: %s", err);

#ifndef WIN32
    /* Create the pipe for comm with the PM */
    if (pipe(fcgi_pm_pipe) < 0) {
	ap_log_error(FCGI_LOG_ERR, s, "FastCGI: pipe() failed");
    }

    /* Spawn the PM only once.  Under Unix, Apache calls init() routines
     * twice, once before detach() and once after.  Win32 doesn't detach.
     * Under DSO, DSO modules are unloaded between the two init() calls.
     * Under Unix, the -X switch causes two calls to init() but no detach
     * (but all subprocesses are wacked so the PM is toasted anyway)! */

    if (ap_standalone && getppid() != 1)
        return;

    /* Start the Process Manager */
    fcgi_pm_pid = ap_spawn_child(p, fcgi_pm_main, NULL, kill_only_once, NULL, NULL, NULL);
    if (fcgi_pm_pid <= 0) {
        ap_log_error(FCGI_LOG_ALERT, s,
            "FastCGI: can't start the process manager, spawn_child() failed");
    }

    close(fcgi_pm_pipe[0]);
#endif
}

static void fcgi_child_init(server_rec *server_conf, pool *p)
{
#ifdef WIN32
	DWORD tid;

    /* Create the Event Handlers */
    fcgi_event_handles[0] = CreateEvent(NULL, FALSE, FALSE, NULL);
    fcgi_event_handles[1] = CreateEvent(NULL, FALSE, FALSE, NULL);
    fcgi_event_handles[2] = CreateEvent(NULL, FALSE, FALSE, NULL);
	fcgi_dynamic_mbox_mutex = CreateMutex(FALSE, FALSE, NULL);

    /* Spawn of the process manager thread */
    fcgi_pm_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)fcgi_pm_main, NULL, 0, &tid);
#endif
    return;
}

static void fcgi_child_exit(server_rec *server_conf, pool *p) {

#ifdef WIN32
	/* Signaling the PM thread tp exit*/
	SetEvent(fcgi_event_handles[TERM_EVENT]);

	/* Waiting on pm thread to exit */
    WaitForSingleObject(fcgi_pm_thread, INFINITE);
#endif

	return;
}

/*
 *----------------------------------------------------------------------
 *
 * get_header_line --
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
static char *get_header_line(char *start, int continuation)
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

    ap_assert(*p != '\0');
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
 * process_headers --
 *
 *      Call with r->parseHeader == SCAN_CGI_READING_HEADERS
 *      and initial script output in fr->header.
 *
 *      If the initial script output does not include the header
 *      terminator ("\r\n\r\n") process_headers returns with no side
 *      effects, to be called again when more script output
 *      has been appended to fr->header.
 *
 *      If the initial script output includes the header terminator,
 *      process_headers parses the headers and determines whether or
 *      not the remaining script output will be sent to the client.
 *      If so, process_headers sends the HTTP response headers to the
 *      client and copies any non-header script output to the output
 *      buffer reqOutbuf.
 *
 * Results:
 *      none.
 *
 * Side effects:
 *      May set r->parseHeader to:
 *        SCAN_CGI_FINISHED -- headers parsed, returning script response
 *        SCAN_CGI_BAD_HEADER -- malformed header from script
 *        SCAN_CGI_INT_REDIRECT -- handler should perform internal redirect
 *        SCAN_CGI_SRV_REDIRECT -- handler should return REDIRECT
 *
 *----------------------------------------------------------------------
 */

static const char *process_headers(request_rec *r, fcgi_request *fr)
{
    char *p, *next, *name, *value;
    int len, flag;
    int hasContentType, hasStatus, hasLocation;

    ap_assert(fr->parseHeader == SCAN_CGI_READING_HEADERS);

    if (fr->header == NULL)
        return NULL;

    /*
     * Do we have the entire header?  Scan for the blank line that
     * terminates the header.
     */
    p = (char *)fr->header->elts;
    len = fr->header->nelts;
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

    /* Return (to be called later when we have more data)
     * if we don't have an entire header. */
    if (flag < 2)
        return NULL;

    /*
     * Parse all the headers.
     */
    fr->parseHeader = SCAN_CGI_FINISHED;
    hasContentType = hasStatus = hasLocation = FALSE;
    next = (char *)fr->header->elts;
    for(;;) {
        next = get_header_line(name = next, TRUE);
        if (*name == '\0') {
            break;
        }
        if ((p = strchr(name, ':')) == NULL) {
            goto BadHeader;
        }
        value = p + 1;
        while (p != name && isspace((unsigned char)*(p - 1))) {
            p--;
        }
        if (p == name) {
            goto BadHeader;
        }
        *p = '\0';
        if (strpbrk(name, " \t") != NULL) {
            *p = ' ';
            goto BadHeader;
        }
        while (isspace((unsigned char)*value)) {
            value++;
        }

        if (strcasecmp(name, "Status") == 0) {
            int statusValue = strtol(value, NULL, 10);

            if (hasStatus) {
                goto DuplicateNotAllowed;
            }
            if (statusValue < 0) {
                fr->parseHeader = SCAN_CGI_BAD_HEADER;
                return ap_psprintf(r->pool, "invalid Status '%s'", value);
            }
            hasStatus = TRUE;
            r->status = statusValue;
            r->status_line = ap_pstrdup(r->pool, value);
            continue;
        }

        if (fr->role == FCGI_RESPONDER) {
            if (strcasecmp(name, "Content-type") == 0) {
                if (hasContentType) {
                    goto DuplicateNotAllowed;
                }
                hasContentType = TRUE;
                r->content_type = ap_pstrdup(r->pool, value);
                continue;
            }

            if (strcasecmp(name, "Location") == 0) {
                if (hasLocation) {
                    goto DuplicateNotAllowed;
                }
                hasLocation = TRUE;
                ap_table_set(r->headers_out, "Location", value);
                continue;
            }

            /* If the script wants them merged, it can do it */
            ap_table_add(r->err_headers_out, name, value);
            continue;
        }
        else {
            ap_table_add(fr->authHeaders, name, value);
        }
    }

    if (fr->role != FCGI_RESPONDER)
        return NULL;

    /*
     * Who responds, this handler or Apache?
     */
    if (hasLocation) {
        const char *location = ap_table_get(r->headers_out, "Location");
        /*
         * Based on internal redirect handling in mod_cgi.c...
         *
         * If a script wants to produce its own Redirect
         * body, it now has to explicitly *say* "Status: 302"
         */
        if (r->status == 200) {
            if(location[0] == '/') {
                /*
                 * Location is an relative path.  This handler will
                 * consume all script output, then have Apache perform an
                 * internal redirect.
                 */
                fr->parseHeader = SCAN_CGI_INT_REDIRECT;
                return NULL;
            } else {
                /*
                 * Location is an absolute URL.  If the script didn't
                 * produce a Content-type header, this handler will
                 * consume all script output and then have Apache generate
                 * its standard redirect response.  Otherwise this handler
                 * will transmit the script's response.
                 */
                fr->parseHeader = SCAN_CGI_SRV_REDIRECT;
                return NULL;
            }
        }
    }
    /*
     * We're responding.  Send headers, buffer excess script output.
     */
    ap_send_http_header(r);

    /* We need to reinstate our timeout, send_http_header() kill()s it */
    ap_hard_timeout("FastCGI request processing", r);

    if (r->header_only)
        return NULL;

    len = fr->header->nelts - (next - fr->header->elts);
    ap_assert(len >= 0);
    ap_assert(BufferLength(fr->clientOutputBuffer) == 0);
    if (BufferFree(fr->clientOutputBuffer) < len) {
        fr->clientOutputBuffer = fcgi_buf_new(r->pool, len);
    }
    ap_assert(BufferFree(fr->clientOutputBuffer) >= len);
    if (len > 0) {
        int sent = fcgi_buf_add_block(fr->clientOutputBuffer, next, len);
        ap_assert(sent == len);
    }
    return NULL;

BadHeader:
    /* Log first line of a multi-line header */
    if ((p = strpbrk(name, "\r\n")) != NULL)
        *p = '\0';
    fr->parseHeader = SCAN_CGI_BAD_HEADER;
    return ap_psprintf(r->pool, "malformed header '%s'", name);

DuplicateNotAllowed:
    fr->parseHeader = SCAN_CGI_BAD_HEADER;
    return ap_psprintf(r->pool, "duplicate header '%s'", name);
}

/*
 * Read from the client filling both the FastCGI server buffer and the
 * client buffer with the hopes of buffering the client data before
 * making the connect() to the FastCGI server.  This prevents slow
 * clients from keeping the FastCGI server in processing longer than is
 * necessary.
 */
static int read_from_client_n_queue(fcgi_request *fr)
{
    char *end;
    unsigned int count;
    long int countRead;

    while (BufferFree(fr->clientInputBuffer) > 0 || BufferFree(fr->serverOutputBuffer) > 0) {
        fcgi_protocol_queue_client_buffer(fr);

        if (fr->expectingClientContent <= 0)
            return OK;

        fcgi_buf_get_free_block_info(fr->clientInputBuffer, &end, &count);
        if (count == 0)
            return OK;

        if ((countRead = ap_get_client_block(fr->r, end, count)) < 0)
            return -1;

        if (countRead == 0)
            fr->expectingClientContent = 0;
        else
            fcgi_buf_add_update(fr->clientInputBuffer, countRead);

    }
    return OK;
}

static int write_to_client(fcgi_request *fr)
{
    char *begin;
    unsigned int count;

    fcgi_buf_get_block_info(fr->clientOutputBuffer, &begin, &count);
    if (count == 0)
        return OK;

    /* If fewer than count bytes are written, an error occured.
     * ap_bwrite() typically forces a flushed write to the client, this
     * effectively results in a block (and short packets) - it should
     * be fixed, but I didn't win much support for the idea on new-httpd.
     * So, without patching Apache, the best way to deal with this is
     * to size the fcgi_bufs to hold all of the script output (within
     * reason) so the script can be released from having to wait around
     * for the transmission to the client to complete. */
#ifdef RUSSIAN_APACHE
    if (ap_rwrite(begin, count, fr->r) != count) {
        ap_log_rerror(FCGI_LOG_INFO, fr->r,
            "FastCGI: client stopped connection before send body completed");
        return -1;
    }
#else
    if (ap_bwrite(fr->r->connection->client, begin, count) != (int) count) {
        ap_log_rerror(FCGI_LOG_INFO, fr->r,
            "FastCGI: client stopped connection before send body completed");
        return -1;
    }
#endif


    /* Don't bother with a wrapped buffer, limiting exposure to slow
     * clients.  The BUFF routines don't allow a writev from above,
     * and don't always memcpy to minimize small write()s, this should
     * be fixed, but I didn't win much support for the idea on
     * new-httpd - I'll have to _prove_ its a problem first.. */

    /* The default behaviour used to be to flush with every write, but this
     * can tie up the FastCGI server longer than is necessary so its an option now */
    if (fr->fs && fr->fs->flush) {
#ifdef RUSSIAN_APACHE
       if (ap_rflush(fr->r)) {
            ap_log_rerror(FCGI_LOG_INFO, fr->r,
                "FastCGI: client stopped connection before send body completed");
            return -1;
        }
#else
       if (ap_bflush(fr->r->connection->client)) {
            ap_log_rerror(FCGI_LOG_INFO, fr->r,
                "FastCGI: client stopped connection before send body completed");
            return -1;
        }
#endif
    }

    fcgi_buf_toss(fr->clientOutputBuffer, count);
    return OK;
}

/*******************************************************************************
 * Determine the user and group suexec should be called with.
 * Based on code in Apache's create_argv_cmd() (util_script.c).
 */
static void set_uid_n_gid(request_rec *r, const char **user, const char **group)
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
            *user = memcpy(ap_pcalloc(r->pool, end - r->uri), r->uri + 1, end - r->uri - 1);
        else
            *user = ap_pstrdup(r->pool, r->uri + 1);
        *group = "-";
    }
    else {
        *user = ap_psprintf(r->pool, "%ld", (long)r->server->server_uid);
        *group = ap_psprintf(r->pool, "%ld", (long)r->server->server_gid);
    }
}

/*******************************************************************************
 * Close the connection to the FastCGI server.  This is normally called by
 * do_work(), but may also be called as in request pool cleanup.
 */
static void close_connection_to_fs(fcgi_request *fr)
{
    pool *rp = fr->r->pool;

    if (fr->fd != -1)
        ap_pclosesocket(rp, fr->fd);

    if (fr->dynamic) {
#ifdef WIN32
        fcgi_rdwr_unlock(fr->lockFd, READER);
#else
        ap_pclosef(rp, fr->lockFd);
#endif

        if (fr->keepReadingFromFcgiApp == FALSE) {
            /* XXX REQ_COMPLETE is only sent for requests which complete
             * normally WRT the fcgi app.  There is no data sent for
             * connect() timeouts or requests which complete abnormally.
             * KillDynamicProcs() and RemoveRecords() need to be looked at
             * to be sure they can reasonably handle these cases before
             * sending these sort of stats - theres some funk in there.
             * XXX We should do something special when this a pool cleanup.
             */
            if (fcgi_util_gettimeofday(&fr->completeTime) < 0) {
                /* there's no point to aborting the request, just log it */
                ap_log_error(FCGI_LOG_ERR, fr->r->server, "FastCGI: gettimeofday() failed");
            } else {
                struct timeval qtime, rtime;

                timersub(&fr->queueTime, &fr->startTime, &qtime);
                timersub(&fr->completeTime, &fr->queueTime, &rtime);
                
                send_to_pm(rp, REQ_COMPLETE, fr->fs_path,
                    fr->user, fr->group,
                    qtime.tv_sec * 1000000 + qtime.tv_usec,
                    rtime.tv_sec * 1000000 + rtime.tv_usec);
            }
        }
    }
}

/*******************************************************************************
 * Connect to the FastCGI server.
 */
static const char *open_connection_to_fs(fcgi_request *fr)
{
    struct timeval  tval;
    fd_set          write_fds, read_fds;
    int             status;
    request_rec * const r = fr->r;
    pool * const rp = r->pool;
    const char *socket_path = NULL;
    struct sockaddr *socket_addr = NULL;
    int socket_addr_len = 0;
#ifdef WIN32
    unsigned long ioctl_arg;
    int errcode;
#else
    int fd_flags = 0;
    const char *err = NULL;
#endif

    /* Create the connection point */
    if (fr->dynamic) {
        socket_path = fcgi_util_socket_hash_filename(rp, fr->fs_path, fr->user, fr->group);
        socket_path = fcgi_util_socket_make_path_absolute(rp, socket_path, 1);

#ifndef WIN32
        err = fcgi_util_socket_make_domain_addr(rp, (struct sockaddr_un **)&socket_addr,
                                      &socket_addr_len, socket_path);
        if (err)
            return err;
#endif
    } else {
#ifdef WIN32
        if (fr->fs->dest_addr != NULL) {
            socket_addr = fr->fs->dest_addr;
        }
        else if (fr->fs->socket_addr) {
            socket_addr = fr->fs->socket_addr;
        }
        else {
            socket_path = fr->fs->socket_path;
        }
#else
        socket_addr = fr->fs->socket_addr;
#endif
        socket_addr_len = fr->fs->socket_addr_len;
    }

    /* Dynamic app's lockfile handling */
    if (fr->dynamic) {
#ifndef WIN32
        const char *lockFileName = fcgi_util_socket_get_lock_filename(rp, socket_path);
        struct stat  lstbuf;
#endif
        struct stat  bstbuf;
        int          result = 0;

        do {
#ifdef WIN32
			if (fr->fs != NULL)
#else
            if (stat(lockFileName, &lstbuf) == 0 &&	S_ISREG(lstbuf.st_mode))
#endif
			{
                if (dynamicAutoUpdate && (stat(fr->fs_path, &bstbuf) == 0)
#ifdef WIN32
					&& ((fr->fs->restartTime > 0) && (fr->fs->restartTime < bstbuf.st_mtime)))
#else
					&& (lstbuf.st_mtime < bstbuf.st_mtime)) 
#endif
                {
                    struct timeval tv = {1, 0};

                    /* Its already running, but there's a newer one,
                     * ask the process manager to start it.
                     * it will notice that the binary is newer,
                     * and do a restart instead.
                     */
                    send_to_pm(rp, PLEASE_START, fr->fs_path, fr->user, fr->group, 0, 0);

                    /* Avoid sleep/alarm interactions */
                    ap_select(0, NULL, NULL, NULL, &tv);
                }
#ifdef WIN32
                fr->lockFd = fr->fs->dynamic_lock;
                result = 1;
#else
                fr->lockFd = ap_popenf(rp, lockFileName, O_APPEND, 0);
                result = (fr->lockFd < 0) ? (0) : (1);
#endif
            } else {
                struct timeval tv = {1, 0};

                send_to_pm(rp, PLEASE_START, fr->fs_path, fr->user, fr->group, 0, 0);

#ifdef WIN32
                Sleep(0);
#else
                /* Avoid sleep/alarm interactions */
                ap_select(0, NULL, NULL, NULL, &tv);
#endif
            }
#ifdef WIN32
            fr->fs = fcgi_util_fs_get_by_id(fr->fs_path, 0, 0);
#endif
        } while (result != 1);

        /* Block until we get a shared (non-exclusive) read Lock */
        if (fcgi_wait_for_shared_read_lock(fr->lockFd) < 0)
            return "failed to obtain a shared read lock on server lockfile";
    }

#ifdef WIN32
    if (socket_path) {

		if (fr->dynamic && fcgi_util_gettimeofday(&fr->startTime) < 0)
	        return "gettimeofday() failed";

        if ((fr->dynamic && dynamicAppConnectTimeout) || (!fr->dynamic && fr->fs->appConnectTimeout)) {
            DWORD interval = (fr->dynamic ? dynamicAppConnectTimeout : fr->fs->appConnectTimeout) * 1000;

            if (!WaitNamedPipe(socket_path, interval))
                return "named pipe failed to connect()";
        }
		else {
			if (! WaitNamedPipe(socket_path, NMPWAIT_WAIT_FOREVER) ) {
				errcode = GetLastError();
				return "named pipe failed to connect()";
			}
		}

        fr->fd = (int) CreateFile(socket_path, GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if ((HANDLE)fr->fd == INVALID_HANDLE_VALUE)
            return "CreateFile() failed";

        ap_note_cleanups_for_h(rp, (HANDLE)fr->fd);

        fr->using_npipe_io = TRUE;

		if (fcgi_util_gettimeofday(&fr->queueTime) < 0)
            return "gettimeofday() failed";


        return NULL;
    }
#endif

    /* Create the socket */
    fr->fd = ap_psocket(rp, socket_addr->sa_family, SOCK_STREAM, 0);

    if (fr->fd < 0)
        return "ap_psocket() failed";

#ifndef WIN32
    if (fr->fd >= FD_SETSIZE) {
        return ap_psprintf(rp, "socket file descriptor (%u) is larger than "
            "FD_SETSIZE (%u), you probably need to rebuild Apache with a "
            "larger FD_SETSIZE", fr->fd, FD_SETSIZE);
    }
#endif

    /* If appConnectTimeout is non-zero, setup do a non-blocking connect */
    if ((fr->dynamic && dynamicAppConnectTimeout) || (!fr->dynamic && fr->fs->appConnectTimeout)) {
#ifndef WIN32
        if ((fd_flags = fcntl(fr->fd, F_GETFL, 0)) < 0)
            return "fcntl(F_GETFL) failed";
        if (fcntl(fr->fd, F_SETFL, fd_flags | O_NONBLOCK) < 0)
            return "fcntl(F_SETFL) failed";
#else
        ioctl_arg =1;
        if (ioctlsocket(fr->fd, FIONBIO, &ioctl_arg) != 0)
            return "ioctlsocket(FIONBIO) failed";
#endif
    }

    if (fr->dynamic && fcgi_util_gettimeofday(&fr->startTime) < 0)
        return "gettimeofday() failed";

    /* Connect */
    if (connect(fr->fd, (struct sockaddr *)socket_addr, socket_addr_len) == 0)
        goto ConnectionComplete;

#ifdef WIN32
    errcode = GetLastError();
    if (errcode != WSAEWOULDBLOCK)
        return "connect() failed";
#else
    /* ECONNREFUSED means the listen queue is full (or there isn't one).
     * With dynamic I can at least make sure the PM knows this is occuring */
    if (fr->dynamic && errno == ECONNREFUSED) {
        /* @@@ This might be better as some other "kind" of message */
        send_to_pm(rp, CONN_TIMEOUT, fr->fs_path, fr->user, fr->group, 0, 0);

        errno = ECONNREFUSED;
    }

    if (errno != EINPROGRESS)
        return "connect() failed";
#endif

    /* The connect() is non-blocking */

    errno = 0;

    if (fr->dynamic) {
        do {
            FD_ZERO(&write_fds);
            FD_SET(fr->fd, &write_fds);
            read_fds = write_fds;
            tval.tv_sec = dynamicPleaseStartDelay;
            tval.tv_usec = 0;

            status = ap_select((fr->fd+1), &read_fds, &write_fds, NULL, &tval);
            if (status < 0)
                break;

            if (fcgi_util_gettimeofday(&fr->queueTime) < 0)
                return "gettimeofday() failed";
            if (status > 0)
                break;

            /* select() timed out */
            send_to_pm(rp, CONN_TIMEOUT, fr->fs_path, fr->user, fr->group, 0, 0);
        } while ((fr->queueTime.tv_sec - fr->startTime.tv_sec) < (int)dynamicAppConnectTimeout);

        /* XXX These can be moved down when dynamic vars live is a struct */
        if (status == 0) {
            return ap_psprintf(rp, "connect() timed out (appConnTimeout=%dsec)",
                dynamicAppConnectTimeout);
        }
    }  /* dynamic */
    else {
        tval.tv_sec = fr->fs->appConnectTimeout;
        tval.tv_usec = 0;
        FD_ZERO(&write_fds);
        FD_SET(fr->fd, &write_fds);
        read_fds = write_fds;

        status = ap_select((fr->fd+1), &read_fds, &write_fds, NULL, &tval);
        if (status == 0) {
            return ap_psprintf(rp, "connect() timed out (appConnTimeout=%dsec)",
                fr->fs->appConnectTimeout);
        }
    }  /* !dynamic */

    if (status < 0)
        return "select() failed";

    if (FD_ISSET(fr->fd, &write_fds) || FD_ISSET(fr->fd, &read_fds)) {
        int error = 0;
        NET_SIZE_T len = sizeof(error);

        if (getsockopt(fr->fd, SOL_SOCKET, SO_ERROR, (char *)&error, &len) < 0)
            /* Solaris pending error */
            return "select() failed (Solaris pending error)";

        if (error != 0) {
            /* Berkeley-derived pending error */
            errno = error;
            return "select() failed (pending error)";
        }
    } else
        return "select() error - THIS CAN'T HAPPEN!";

ConnectionComplete:
    /* Return to blocking mode if it was set up */
    if ((fr->dynamic && dynamicAppConnectTimeout) || (!fr->dynamic && fr->fs->appConnectTimeout)) {
#ifdef WIN32
        ioctl_arg = 0;
        if (ioctlsocket(fr->fd, FIONBIO, &ioctl_arg) != 0)
            return "ioctlsocket(FIONBIO) failed";
#else
        if ((fcntl(fr->fd, F_SETFL, fd_flags)) < 0)
            return "fcntl(F_SETFL) failed";
#endif
    }

#ifdef TCP_NODELAY
    if (socket_addr->sa_family == AF_INET) {
        /* We shouldn't be sending small packets and there's no application
         * level ack of the data we send, so disable Nagle */
        int set = 1;
        setsockopt(fr->fd, IPPROTO_TCP, TCP_NODELAY, (char *)&set, sizeof(set));
    }
#endif

    return NULL;
}

static int server_error(fcgi_request *fr)
{
#if defined(SIGPIPE) && MODULE_MAGIC_NUMBER < 19990320
    /* Make sure we leave with Apache's sigpipe_handler in place */
    if (fr->apache_sigpipe_handler != NULL)
        signal(SIGPIPE, fr->apache_sigpipe_handler);
#endif
    close_connection_to_fs(fr);
    ap_kill_timeout(fr->r);
    return SERVER_ERROR;
}

static void log_fcgi_server_stderr(void *data)
{
    const fcgi_request * const fr = (fcgi_request *)data;

    if (fr == NULL)
        return ;

    if (fr->fs_stderr_len) {
        ap_log_rerror(FCGI_LOG_ERR_NOERRNO, fr->r,
            "FastCGI: server \"%s\" stderr: %s", fr->fs_path, fr->fs_stderr);
    }
}

/*----------------------------------------------------------------------
 * This is the core routine for moving data between the FastCGI
 * application and the Web server's client.
 */
static int do_work(request_rec *r, fcgi_request *fr)
{
    struct timeval  timeOut, dynamic_last_activity_time = {0, 0};
    fd_set  read_set, write_set;
    int     status = 0, idle_timeout;
    int     numFDs, dynamic_first_read = fr->dynamic ? 1 : 0;
    int     doClientWrite;
    int     envSent = FALSE;    /* has the complete ENV been buffered? */
    env_status env;
    pool *rp = r->pool;
    const char *err = NULL;

    FD_ZERO(&read_set);
    FD_ZERO(&write_set);

    fcgi_protocol_queue_begin_request(fr);

    /* Buffer as much of the environment as we can fit */
    env.envp = NULL;
    envSent = fcgi_protocol_queue_env(r, fr, &env);

    /* Start the Apache dropdead timer.  See comments at top of file. */
    ap_hard_timeout("buffering of FastCGI client data", r);

    /* Read as much as possible from the client. */
    if (fr->role == FCGI_RESPONDER) {
        status = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR);
        if (status != OK) {
            ap_kill_timeout(r);
            return status;
        }
        fr->expectingClientContent = (ap_should_client_block(r) != 0);

        if (read_from_client_n_queue(fr) != OK)
            return server_error(fr);
    }

    /* Connect to the FastCGI Application */
    ap_hard_timeout("connect() to FastCGI server", r);
    if ((err = open_connection_to_fs(fr))) {
        ap_log_rerror(FCGI_LOG_ERR, r,
            "FastCGI: failed to connect to server \"%s\": %s", fr->fs_path, err);
        return server_error(fr);
    }

    numFDs = fr->fd + 1;
    idle_timeout = fr->dynamic ? dynamic_idle_timeout : fr->fs->idle_timeout;

    if (dynamic_first_read) {
        dynamic_last_activity_time = fr->startTime;

        if (dynamicAppConnectTimeout) {
            struct timeval qwait;
            timersub(&fr->queueTime, &fr->startTime, &qwait);
            dynamic_first_read = qwait.tv_sec / dynamicPleaseStartDelay + 1;
        }
    }

    /* @@@ We never reset the timer in this loop, most folks don't mess w/
     * Timeout directive which means we've got the 5 min default which is way
     * to long to tie up a fs.  We need a better/configurable solution that
     * uses the select */
    ap_hard_timeout("FastCGI request processing", r);

    /* Register to get the script's stderr logged at the end of the request */
    ap_block_alarms();
    ap_register_cleanup(rp, (void *)fr, log_fcgi_server_stderr, ap_null_cleanup);
    ap_unblock_alarms();

    /* The socket is writeable, so get the first write out of the way */
    if (fcgi_buf_get_to_fd(fr->serverOutputBuffer, fr->fd) < 0) {
            ap_log_rerror(FCGI_LOG_ERR, r,
                "FastCGI: comm with server \"%s\" aborted: write failed", fr->fs_path);
            return server_error(fr);
    }

    while (fr->keepReadingFromFcgiApp
            || BufferLength(fr->serverInputBuffer) > 0
            || BufferLength(fr->clientOutputBuffer) > 0) {

        /* If we didn't buffer all of the environment yet, buffer some more */
        if (!envSent)
            envSent = fcgi_protocol_queue_env(r, fr, &env);

        /* Read as much as possible from the client. */
        if (fr->role == FCGI_RESPONDER && !fr->eofSent && envSent) {
            if (read_from_client_n_queue(fr) != OK)
                return server_error(fr);
        }

        /* To avoid deadlock, don't do a blocking select to write to
         * the FastCGI application without selecting to read from the
         * FastCGI application.
         */
        doClientWrite = FALSE;
        if (fr->keepReadingFromFcgiApp && BufferFree(fr->serverInputBuffer) > 0) {

#ifdef WIN32
            if (!fr->using_npipe_io) {
#endif
            FD_SET(fr->fd, &read_set);

            /* Is data buffered for output to the FastCGI server? */
            if (BufferLength(fr->serverOutputBuffer) > 0) {
                FD_SET(fr->fd, &write_set);
            } else {
                FD_CLR(fr->fd, &write_set);
            }
#ifdef WIN32
			}
#endif
            /*
             * If there's data buffered to send to the client, don't
             * wait indefinitely for the FastCGI app; the app might
             * be doing server push.
             */
	    if (BufferLength(fr->clientOutputBuffer) > 0) {
                timeOut.tv_sec = 0;
                timeOut.tv_usec = 100000;        /* 0.1 sec */
            }
	    else if (dynamic_first_read) {
                int delay;
                struct timeval qwait;

                if (fcgi_util_gettimeofday(&fr->queueTime) < 0) {
                    ap_log_rerror(FCGI_LOG_ERR, r, "FastCGI: gettimeofday() failed");
                    return server_error(fr);
				}

                /* Check for idle_timeout */
                if (status) {
                    dynamic_last_activity_time = fr->queueTime;
                }
                else {
                    struct timeval idle_time;
                    timersub(&fr->queueTime, &dynamic_last_activity_time, &idle_time);
                    if (idle_time.tv_sec > idle_timeout) {
                        send_to_pm(rp, CONN_TIMEOUT, fr->fs_path, fr->user, fr->group, 0, 0);
                        ap_log_rerror(FCGI_LOG_ERR, r,
                            "FastCGI: comm with (dynamic) server \"%s\" aborted: (first read) idle timeout (%d sec)",
                            fr->fs_path, idle_timeout);
                        return server_error(fr);
                    }
                }

                timersub(&fr->queueTime, &fr->startTime, &qwait);

                delay = dynamic_first_read * dynamicPleaseStartDelay;
                if (qwait.tv_sec < delay) {
                    timeOut.tv_sec = delay;
                    timeOut.tv_usec = 100000;  /* fudge for select() slop */
                    timersub(&timeOut, &qwait, &timeOut);
                }
                else {
                    /* Killed time somewhere.. client read? */
                    send_to_pm(rp, CONN_TIMEOUT, fr->fs_path, fr->user, fr->group, 0, 0);
                    dynamic_first_read = qwait.tv_sec / dynamicPleaseStartDelay + 1;
                    timeOut.tv_sec = dynamic_first_read * dynamicPleaseStartDelay;
                    timeOut.tv_usec = 100000;  /* fudge for select() slop */
                    timersub(&timeOut, &qwait, &timeOut);
                }
            }
            else {
                timeOut.tv_sec = idle_timeout;
                timeOut.tv_usec = 0;
            }

#ifdef WIN32
            if (!fr->using_npipe_io) {
#endif
            if ((status = ap_select(numFDs, &read_set, &write_set, NULL, &timeOut)) < 0) {
                ap_log_rerror(FCGI_LOG_ERR, r,
                    "FastCGI: comm with server \"%s\" aborted: select() failed", fr->fs_path);
                return server_error(fr);
            }
#ifdef WIN32
            }
            else {
                int stopTime = time(NULL) + timeOut.tv_sec;
                DWORD bytesavail=0;

                if (!(BufferLength(fr->serverOutputBuffer) > 0)) {
                    status = 0;

                    while ((timeOut.tv_sec != 0) && (time(NULL) <= stopTime)) {
                        if (PeekNamedPipe((HANDLE) fr->fd,NULL, 0, NULL, &bytesavail, NULL) &&
                            bytesavail > 0) 
                        {
                            status =1;
                            break;
                        }
                        Sleep(100);
                    }
                }
                else {
                    status = 1;
                }
            }
#endif

            if (status == 0) {
                if (BufferLength(fr->clientOutputBuffer) > 0) {
                    doClientWrite = TRUE;
                }
                else if (dynamic_first_read) {
                    struct timeval qwait;

                    if (fcgi_util_gettimeofday(&fr->queueTime) < 0) {
                    	ap_log_rerror(FCGI_LOG_ERR, r, "FastCGI: gettimeofday() failed");
                    	return server_error(fr);
					}

                    timersub(&fr->queueTime, &fr->startTime, &qwait);

                    send_to_pm(rp, CONN_TIMEOUT, fr->fs_path, fr->user, fr->group, 0, 0);

                    dynamic_first_read = qwait.tv_sec / dynamicPleaseStartDelay + 1;
                }
                else {
                    ap_log_rerror(FCGI_LOG_ERR, r,
                        "FastCGI: comm with server \"%s\" aborted: idle timeout (%d sec)",
                        fr->fs_path, idle_timeout);
                    return server_error(fr);
                }
            }

#if defined(SIGPIPE) && MODULE_MAGIC_NUMBER < 19990320
            /* Disable Apache's SIGPIPE handler */
            fr->apache_sigpipe_handler = signal(SIGPIPE, SIG_IGN);
#endif

            /* Read from the FastCGI server */
#ifdef WIN32
            if (((fr->using_npipe_io) &&
                (BufferFree(fr->serverInputBuffer) > 0)) || FD_ISSET(fr->fd, &read_set)) {
#else
            if (FD_ISSET(fr->fd, &read_set)) {
#endif             
                if (dynamic_first_read) {
                    dynamic_first_read = 0;
                    if (fcgi_util_gettimeofday(&fr->queueTime) < 0) {
                        ap_log_rerror(FCGI_LOG_ERR, r, "FastCGI: gettimeofday() failed");
                        return server_error(fr);
		    }
               }

                if ((status = fcgi_buf_add_fd(fr->serverInputBuffer, fr->fd)) < 0) {
                    ap_log_rerror(FCGI_LOG_ERR, r,
                        "FastCGI: comm with server \"%s\" aborted: read failed", fr->fs_path);
                    return server_error(fr);
                }

                if (status == 0) {
                    fr->keepReadingFromFcgiApp = FALSE;
                    close_connection_to_fs(fr);
                }
            }

            /* Write to the FastCGI server */
#ifdef WIN32
            if (((fr->using_npipe_io) &&
                (BufferLength(fr->serverOutputBuffer) > 0)) || FD_ISSET(fr->fd, &write_set)) {
#else
            if (FD_ISSET(fr->fd, &write_set)) {
#endif

                if (fcgi_buf_get_to_fd(fr->serverOutputBuffer, fr->fd) < 0) {
                    ap_log_rerror(FCGI_LOG_ERR, r,
                        "FastCGI: comm with server \"%s\" aborted: write failed", fr->fs_path);
                    return server_error(fr);
                }
            }

#if defined(SIGPIPE) && MODULE_MAGIC_NUMBER < 19990320
            /* Reinstall Apache's SIGPIPE handler */
            signal(SIGPIPE, fr->apache_sigpipe_handler);
#endif

        } else {
            doClientWrite = TRUE;
        }

        if (fr->role == FCGI_RESPONDER && doClientWrite) {
            if (write_to_client(fr) != OK) {
                #if defined(SIGPIPE) && MODULE_MAGIC_NUMBER < 19990320
                    /* Make sure we leave with Apache's sigpipe_handler in place */
                    if (fr->apache_sigpipe_handler != NULL)
                        signal(SIGPIPE, fr->apache_sigpipe_handler);
                #endif
                    close_connection_to_fs(fr);
                    ap_kill_timeout(fr->r);
                    return OK;
            }
        }

        if (fcgi_protocol_dequeue(rp, fr) != OK)
            return server_error(fr);

        if (fr->keepReadingFromFcgiApp && fr->exitStatusSet) {
            /* we're done talking to the fcgi app */
            fr->keepReadingFromFcgiApp = FALSE;
            close_connection_to_fs(fr);
        }

        if (fr->parseHeader == SCAN_CGI_READING_HEADERS) {
            if ((err = process_headers(r, fr))) {
                ap_log_rerror(FCGI_LOG_ERR, r,
                    "FastCGI: comm with server \"%s\" aborted: error parsing headers: %s", fr->fs_path, err);
                return server_error(fr);
            }
        }

    } /* while */

    switch (fr->parseHeader) {

        case SCAN_CGI_FINISHED:
            if (fr->role == FCGI_RESPONDER) {
#ifdef RUSSIAN_APACHE
                ap_rflush(r);
#else
                ap_bflush(r->connection->client);
#endif
                ap_bgetopt(r->connection->client, BO_BYTECT, &r->bytes_sent);
            }
            break;

        case SCAN_CGI_READING_HEADERS:
            ap_log_rerror(FCGI_LOG_ERR, r,
                "FastCGI: incomplete headers (%d bytes) received from server \"%s\"",
                fr->header->nelts, fr->fs_path);
            return server_error(fr);

        case SCAN_CGI_BAD_HEADER:
            return server_error(fr);

        case SCAN_CGI_INT_REDIRECT:
        case SCAN_CGI_SRV_REDIRECT:
            /*
             * XXX We really should be soaking all client input
             * and all script output.  See mod_cgi.c.
             * There's other differences we need to pick up here as well!
             * This has to be revisited.
             */
            break;

        default:
            ap_assert(FALSE);
    }

    ap_kill_timeout(r);
    return OK;
}


static fcgi_request *create_fcgi_request(request_rec * const r, const char *fs_path)
{
    struct stat *my_finfo;
    pool * const p = r->pool;
    fcgi_server *fs;
    fcgi_request * const fr = (fcgi_request *)ap_pcalloc(p, sizeof(fcgi_request));

    if (fs_path) {
        my_finfo = (struct stat *)ap_palloc(p, sizeof(struct stat));
        if (stat(fs_path, my_finfo) < 0) {
            ap_log_rerror(FCGI_LOG_ERR, r, "FastCGI: stat() of \"%s\" failed", fs_path);
            return NULL;
        }
    }
    else {
        my_finfo = &r->finfo;
        fs_path = r->filename;
    }

    fs = fcgi_util_fs_get_by_id(fs_path, r->server->server_uid, r->server->server_gid);
    if (fs == NULL) {
        /* Its a request for a dynamic FastCGI application */
        const char * const err =
            fcgi_util_fs_is_path_ok(p, fs_path, my_finfo, r->server->server_uid, r->server->server_gid);

        if (err) {
            ap_log_rerror(FCGI_LOG_ERR_NOERRNO, r, "FastCGI: invalid (dynamic) server \"%s\": %s", fs_path, err);
            return NULL;
        }
    }

    fr->serverInputBuffer = fcgi_buf_new(p, SERVER_BUFSIZE);
    fr->serverOutputBuffer = fcgi_buf_new(p, SERVER_BUFSIZE);
    fr->clientInputBuffer = fcgi_buf_new(p, SERVER_BUFSIZE);
    fr->clientOutputBuffer = fcgi_buf_new(p, SERVER_BUFSIZE);
    fr->erBufPtr = fcgi_buf_new(p, sizeof(FCGI_EndRequestBody) + 1);
    fr->gotHeader = FALSE;
    fr->parseHeader = SCAN_CGI_READING_HEADERS;
    fr->header = ap_make_array(p, 1, 1);
    fr->fs_stderr = NULL;
    fr->r = r;
    fr->readingEndRequestBody = FALSE;
    fr->exitStatus = 0;
    fr->exitStatusSet = FALSE;
    fr->requestId = 1; /* anything but zero is OK here */
    fr->eofSent = FALSE;
    fr->role = FCGI_RESPONDER;
    fr->expectingClientContent = FALSE;
    fr->keepReadingFromFcgiApp = TRUE;
    fr->fs = fs;
    fr->fs_path = fs_path;
    fr->authHeaders = ap_make_table(p, 10);
#ifdef WIN32
    fr->fd = INVALID_SOCKET;
    fr->dynamic = ((fs == NULL) || (fs->directive == APP_CLASS_DYNAMIC)) ? TRUE : FALSE;
    fr->using_npipe_io = FALSE;
#else
    fr->dynamic = (fs == NULL) ? TRUE : FALSE;
    fr->fd = -1;
#endif

    set_uid_n_gid(r, &fr->user, &fr->group);

    return fr;
}

/*
 *----------------------------------------------------------------------
 *
 * handler --
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
static int apache_is_scriptaliased(request_rec *r)
{
    const char *t = ap_table_get(r->notes, "alias-forced-type");
    return t && (!strcasecmp(t, "cgi-script"));
}

/* If a script wants to produce its own Redirect body, it now
 * has to explicitly *say* "Status: 302".  If it wants to use
 * Apache redirects say "Status: 200".  See process_headers().
 */
static int post_process_for_redirects(request_rec * const r,
    const fcgi_request * const fr)
{
    switch(fr->parseHeader) {
        case SCAN_CGI_INT_REDIRECT:

            /* @@@ There are still differences between the handling in
             * mod_cgi and mod_fastcgi.  This needs to be revisited.
             */
            /* We already read the message body (if any), so don't allow
             * the redirected request to think it has one.  We can ignore
             * Transfer-Encoding, since we used REQUEST_CHUNKED_ERROR.
             */
            r->method = "GET";
            r->method_number = M_GET;
            ap_table_unset(r->headers_in, "Content-length");

            ap_internal_redirect_handler(ap_table_get(r->headers_out, "Location"), r);
            return OK;

        case SCAN_CGI_SRV_REDIRECT:
            return REDIRECT;

        default:
            return OK;
    }
}

/******************************************************************************
 * Process fastcgi-script requests.  Based on mod_cgi::cgi_handler().
 */
static int content_handler(request_rec *r)
{
    fcgi_request *fr = NULL;
    int ret;

    /* Setup a new FastCGI request */
    if ((fr = create_fcgi_request(r, NULL)) == NULL)
        return SERVER_ERROR;

    /* If its a dynamic invocation, make sure scripts are OK here */
    if (fr->dynamic && !(ap_allow_options(r) & OPT_EXECCGI) && !apache_is_scriptaliased(r)) {
        ap_log_rerror(FCGI_LOG_ERR_NOERRNO, r,
            "FastCGI: \"ExecCGI Option\" is off in this directory: %s", r->uri);
        return SERVER_ERROR;
    }

    /* Process the fastcgi-script request */
    if ((ret = do_work(r, fr)) != OK)
        return ret;

    /* Special case redirects */
    return post_process_for_redirects(r, fr);
}


static int post_process_auth_passed_header(table *t, const char *key, const char * const val)
{
	if (strncasecmp(key, "Variable-", 9) == 0)
        key += 9;

    ap_table_setn(t, key, val);
    return 1;
}

static int post_process_auth_passed_compat_header(table *t, const char *key, const char * const val)
{
	if (strncasecmp(key, "Variable-", 9) == 0)
        ap_table_setn(t, key + 9, val);

    return 1;
}

static int post_process_auth_failed_header(table * const t, const char * const key, const char * const val)
{
    ap_table_setn(t, key, val);
    return 1;
}

static void post_process_auth(fcgi_request * const fr, const int passed)
{
    request_rec * const r = fr->r;

    /* Restore the saved subprocess_env because we muddied ours up */
    r->subprocess_env = fr->saved_subprocess_env;

    if (passed) {
        if (fr->auth_compat) {
            ap_table_do((int (*)(void *, const char *, const char *))post_process_auth_passed_compat_header,
                 (void *)r->subprocess_env, fr->authHeaders, NULL);
        }
        else {
            ap_table_do((int (*)(void *, const char *, const char *))post_process_auth_passed_header,
                 (void *)r->subprocess_env, fr->authHeaders, NULL);
        }
    }
    else {
        ap_table_do((int (*)(void *, const char *, const char *))post_process_auth_failed_header,
             (void *)r->err_headers_out, fr->authHeaders, NULL);
    }

    /* @@@ Restore these.. its a hack until I rewrite the header handling */
    r->status = HTTP_OK;
    r->status_line = NULL;
}

static int check_user_authentication(request_rec *r)
{
    int res, authenticated = 0;
    const char *password;
    fcgi_request *fr;
    const fcgi_dir_config * const dir_config =
        (const fcgi_dir_config *)ap_get_module_config(r->per_dir_config, &fastcgi_module);

    if (dir_config->authenticator == NULL)
	    return DECLINED;

    /* Get the user password */
    if ((res = ap_get_basic_auth_pw(r, &password)) != OK)
        return res;

    if ((fr = create_fcgi_request(r, dir_config->authenticator)) == NULL)
        return SERVER_ERROR;

    /* Save the existing subprocess_env, because we're gonna muddy it up */
    fr->saved_subprocess_env = ap_copy_table(r->pool, r->subprocess_env);

    ap_table_setn(r->subprocess_env, "REMOTE_PASSWD", password);
    ap_table_setn(r->subprocess_env, "FCGI_APACHE_ROLE", "AUTHENTICATOR");

    /* The FastCGI Protocol doesn't differentiate authentication */
    fr->role = FCGI_AUTHORIZER;

    /* Do we need compatibility mode? */
    fr->auth_compat = (dir_config->authenticator_options & FCGI_COMPAT);

    if ((res = do_work(r, fr)) != OK)
        goto AuthenticationFailed;

    authenticated = (r->status == 200);
    post_process_auth(fr, authenticated);

    /* A redirect shouldn't be allowed during the authentication phase */
    if (ap_table_get(r->headers_out, "Location") != NULL) {
        ap_log_rerror(FCGI_LOG_ERR_NOERRNO, r,
            "FastCGI: FastCgiAuthenticator \"%s\" redirected (not allowed)",
            dir_config->authenticator);
        goto AuthenticationFailed;
    }

    if (authenticated)
        return OK;

AuthenticationFailed:
    if (!(dir_config->authenticator_options & FCGI_AUTHORITATIVE))
        return DECLINED;

    /* @@@ Probably should support custom_responses */
    ap_note_basic_auth_failure(r);
    ap_log_rerror(FCGI_LOG_ERR_NOERRNO, r,
        "FastCGI: authentication failed for user \"%s\": %s", r->connection->user, r->uri);
    return (res == OK) ? AUTH_REQUIRED : res;
}

static int check_user_authorization(request_rec *r)
{
    int res, authorized = 0;
    fcgi_request *fr;
    const fcgi_dir_config * const dir_config =
        (const fcgi_dir_config *)ap_get_module_config(r->per_dir_config, &fastcgi_module);

    if (dir_config->authorizer == NULL)
	    return DECLINED;

    /* @@@ We should probably honor the existing parameters to the require directive
     * as well as allow the definition of new ones (or use the basename of the
     * FastCGI server and pass the rest of the directive line), but for now keep
     * it simple. */

    if ((fr = create_fcgi_request(r, dir_config->authorizer)) == NULL)
        return SERVER_ERROR;

    /* Save the existing subprocess_env, because we're gonna muddy it up */
    fr->saved_subprocess_env = ap_copy_table(r->pool, r->subprocess_env);

    ap_table_setn(r->subprocess_env, "FCGI_APACHE_ROLE", "AUTHORIZER");

    fr->role = FCGI_AUTHORIZER;

    /* Do we need compatibility mode? */
    fr->auth_compat = (dir_config->authenticator_options & FCGI_COMPAT);

    if ((res = do_work(r, fr)) != OK)
        goto AuthorizationFailed;

    authorized = (r->status == 200);
    post_process_auth(fr, authorized);

    /* A redirect shouldn't be allowed during the authorization phase */
    if (ap_table_get(r->headers_out, "Location") != NULL) {
        ap_log_rerror(FCGI_LOG_ERR_NOERRNO, r,
            "FastCGI: FastCgiAuthorizer \"%s\" redirected (not allowed)",
            dir_config->authorizer);
        goto AuthorizationFailed;
    }

    if (authorized)
        return OK;

AuthorizationFailed:
    if (!(dir_config->authorizer_options & FCGI_AUTHORITATIVE))
        return DECLINED;

    /* @@@ Probably should support custom_responses */
    ap_note_basic_auth_failure(r);
    ap_log_rerror(FCGI_LOG_ERR_NOERRNO, r,
        "FastCGI: authorization failed for user \"%s\": %s", r->connection->user, r->uri);
    return (res == OK) ? AUTH_REQUIRED : res;
}

static int check_access(request_rec *r)
{
    int res, access_allowed = 0;
    fcgi_request *fr;
    const fcgi_dir_config * const dir_config =
        (fcgi_dir_config *)ap_get_module_config(r->per_dir_config, &fastcgi_module);

    if (dir_config == NULL || dir_config->access_checker == NULL)
		return DECLINED;

    if ((fr = create_fcgi_request(r, dir_config->access_checker)) == NULL)
        return SERVER_ERROR;

    /* Save the existing subprocess_env, because we're gonna muddy it up */
    fr->saved_subprocess_env = ap_copy_table(r->pool, r->subprocess_env);

    ap_table_setn(r->subprocess_env, "FCGI_APACHE_ROLE", "ACCESS_CHECKER");

    /* The FastCGI Protocol doesn't differentiate access control */
    fr->role = FCGI_AUTHORIZER;

    /* Do we need compatibility mode? */
    fr->auth_compat = (dir_config->authenticator_options & FCGI_COMPAT);

    if ((res = do_work(r, fr)) != OK)
        goto AccessFailed;

    access_allowed = (r->status == 200);
    post_process_auth(fr, access_allowed);

    /* A redirect shouldn't be allowed during the access check phase */
    if (ap_table_get(r->headers_out, "Location") != NULL) {
        ap_log_rerror(FCGI_LOG_ERR_NOERRNO, r,
            "FastCGI: FastCgiAccessChecker \"%s\" redirected (not allowed)",
            dir_config->access_checker);
        goto AccessFailed;
    }

    if (access_allowed)
        return OK;

AccessFailed:
    if (!(dir_config->access_checker_options & FCGI_AUTHORITATIVE))
        return DECLINED;

    /* @@@ Probably should support custom_responses */
    ap_log_rerror(FCGI_LOG_ERR_NOERRNO, r, "FastCGI: access denied: %s", r->uri);
    return (res == OK) ? FORBIDDEN : res;
}



command_rec fastcgi_cmds[] = {
    { "AppClass",      fcgi_config_new_static_server, NULL, RSRC_CONF, RAW_ARGS, NULL },
    { "FastCgiServer", fcgi_config_new_static_server, NULL, RSRC_CONF, RAW_ARGS, NULL },

    { "ExternalAppClass",      fcgi_config_new_external_server, NULL, RSRC_CONF, RAW_ARGS, NULL },
    { "FastCgiExternalServer", fcgi_config_new_external_server, NULL, RSRC_CONF, RAW_ARGS, NULL },

    { "FastCgiIpcDir", fcgi_config_set_socket_dir, NULL, RSRC_CONF, TAKE1, NULL },

    { "FastCgiSuexec", fcgi_config_set_suexec, NULL, RSRC_CONF, TAKE1, NULL },

    { "FCGIConfig",    fcgi_config_set_config, NULL, RSRC_CONF, RAW_ARGS, NULL },
    { "FastCgiConfig", fcgi_config_set_config, NULL, RSRC_CONF, RAW_ARGS, NULL },

    { "FastCgiAuthenticator", fcgi_config_new_auth_server,
        (void *)FCGI_AUTH_TYPE_AUTHENTICATOR, ACCESS_CONF, TAKE12,
        "a fastcgi-script path (absolute or relative to ServerRoot) followed by an optional -compat" },
    { "FastCgiAuthenticatorAuthoritative", fcgi_config_set_authoritative_slot,
        (void *)XtOffsetOf(fcgi_dir_config, authenticator_options), ACCESS_CONF, FLAG,
        "Set to 'off' to allow authentication to be passed along to lower modules upon failure" },

    { "FastCgiAuthorizer", fcgi_config_new_auth_server,
        (void *)FCGI_AUTH_TYPE_AUTHORIZER, ACCESS_CONF, TAKE12,
        "a fastcgi-script path (absolute or relative to ServerRoot) followed by an optional -compat" },
    { "FastCgiAuthorizerAuthoritative", fcgi_config_set_authoritative_slot,
        (void *)XtOffsetOf(fcgi_dir_config, authorizer_options), ACCESS_CONF, FLAG,
        "Set to 'off' to allow authorization to be passed along to lower modules upon failure" },

    { "FastCgiAccessChecker", fcgi_config_new_auth_server,
        (void *)FCGI_AUTH_TYPE_ACCESS_CHECKER, ACCESS_CONF, TAKE12,
        "a fastcgi-script path (absolute or relative to ServerRoot) followed by an optional -compat" },
    { "FastCgiAccessCheckerAuthoritative", fcgi_config_set_authoritative_slot,
        (void *)XtOffsetOf(fcgi_dir_config, access_checker_options), ACCESS_CONF, FLAG,
        "Set to 'off' to allow access control to be passed along to lower modules upon failure" },
    { NULL }
};


handler_rec fastcgi_handlers[] = {
    { FCGI_MAGIC_TYPE, content_handler },
    { "fastcgi-script", content_handler },
    { NULL }
};


module MODULE_VAR_EXPORT fastcgi_module = {
    STANDARD_MODULE_STUFF,
    init_module,              /* initializer */
    fcgi_config_create_dir_config,    /* per-dir config creator */
    NULL,                      /* per-dir config merger (default: override) */
    NULL,                      /* per-server config creator */
    NULL,                      /* per-server config merger (default: override) */
    fastcgi_cmds,              /* command table */
    fastcgi_handlers,          /* [9] content handlers */
    NULL,                      /* [2] URI-to-filename translation */
    check_user_authentication, /* [5] authenticate user_id */
    check_user_authorization,  /* [6] authorize user_id */
    check_access,              /* [4] check access (based on src & http headers) */
    NULL,                      /* [7] check/set MIME type */
    NULL,                      /* [8] fixups */
    NULL,                      /* [10] logger */
    NULL,                      /* [3] header-parser */
    fcgi_child_init,           /* process initialization */
    fcgi_child_exit,           /* process exit/cleanup */
    NULL                       /* [1] post read-request handling */
};
