/*
 * $Id: fcgi_pm.c,v 1.57 2001/05/31 13:16:38 robs Exp $
 */


#include "fcgi.h"

#ifdef _HPUX_SOURCE
#include <unistd.h>
#define seteuid(arg) setresuid(-1, (arg), -1)
#endif

int fcgi_dynamic_total_proc_count = 0;    /* number of running apps */
time_t fcgi_dynamic_epoch = 0;            /* last time kill_procs was
                                           * invoked by process mgr */
time_t fcgi_dynamic_last_analyzed = 0;    /* last time calculation was
                                           * made for the dynamic procs */

static time_t now = 0;

#ifdef WIN32
#pragma warning ( disable : 4100 4102 )
static BOOL bTimeToDie = FALSE;  /* process termination flag */
HANDLE fcgi_event_handles[3];
#ifndef SIGKILL
#define SIGKILL 9
#endif
#endif


#ifndef WIN32
static int seteuid_root(void)
{
    int rc = seteuid((uid_t)0);
    if (rc == -1) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
            "FastCGI: seteuid(0) failed");
    }
    return rc;
}

static int seteuid_user(void)
{
    int rc = seteuid(ap_user_id);
    if (rc == -1) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
            "FastCGI: seteuid(%u) failed", (unsigned)ap_user_id);
    }
    return rc;
}
#endif

/*
 * Signal the process to exit.  How (or if) the process responds
 * depends on the FastCGI application library (esp. on Win32) and
 * possibly application code (signal handlers and whether or not
 * SA_RESTART is on).  At any rate, we send the signal with the
 * hopes that the process will exit on its own.  Later, as we 
 * review the state of application processes, if we see one marked 
 * for death, but that hasn't died within a specified period of
 * time, fcgi_kill() is called again with a KILL)
 */
static void fcgi_kill(ServerProcess *process, int sig)
{
    FCGIDBG3("fcgi_kill(%ld, %d)", process->pid, sig);

    process->state = FCGI_VICTIM_STATE;                

#ifdef WIN32
    if (sig == SIGTERM)
    {
        SetEvent(process->terminationEvent);
    }
    else if (sig == SIGKILL)
    {
        TerminateProcess(process->handle, 1);
    }
    else
    {
        ap_assert(0);
    }
#else
    if (fcgi_wrapper) 
    {
        seteuid_root();
    }

    kill(process->pid, sig);

    if (fcgi_wrapper) 
    {
        seteuid_user();
    }
#endif
}

/*******************************************************************************
 * Send SIGTERM to each process in the server class, remove socket
 * file if appropriate.  Currently this is only called when the PM is shutting
 * down and thus memory isn't freed and sockets and files aren't closed.
 */
static void shutdown_all()
{
    fcgi_server *s = fcgi_servers;
    
    while (s) 
    {
        ServerProcess *proc = s->procs;
        int i;
        int numChildren = (s->directive == APP_CLASS_DYNAMIC)
            ? dynamicMaxClassProcs
            : s->numProcesses;
        
        /* Remove the socket file */
        if (s->socket_path != NULL && s->directive != APP_CLASS_EXTERNAL) {
#ifndef WIN32
            if (unlink(s->socket_path) != 0 && errno != ENOENT) {
                ap_log_error(FCGI_LOG_ERR, fcgi_apache_main_server,
                    "FastCGI: unlink() failed to remove socket file \"%s\" for%s server \"%s\"",
                    s->socket_path,
                    (s->directive == APP_CLASS_DYNAMIC) ? " (dynamic)" : "", s->fs_path);
            }
#else
           CloseHandle((HANDLE)s->listenFd);
#endif
        }

        /* Send TERM to all processes */
        for (i = 0; i < numChildren; i++, proc++) 
        {
            if (proc->state == FCGI_RUNNING_STATE) 
            {
                fcgi_kill(proc, SIGTERM);
            }
        }
        
        s = s->next;
    }
}

static int init_listen_sock(fcgi_server * fs)
{
    ap_assert(fs->directive != APP_CLASS_EXTERNAL);

    /* Create the socket */
    if ((fs->listenFd = ap_psocket(fcgi_config_pool, fs->socket_addr->sa_family, SOCK_STREAM, 0)) < 0) 
    {
#ifdef WIN32
        errno = WSAGetLastError();  // Not sure if this will work as expected
#endif
        ap_log_error(FCGI_LOG_CRIT_ERRNO, fcgi_apache_main_server,
            "FastCGI: can't create %sserver \"%s\": socket() failed", 
            (fs->directive == APP_CLASS_DYNAMIC) ? "(dynamic) " : "",
            fs->fs_path);
        return -1;
    }

#ifndef WIN32
    if (fs->socket_addr->sa_family == AF_UNIX) 
    {
        /* Remove any existing socket file.. just in case */
        unlink(((struct sockaddr_un *)fs->socket_addr)->sun_path);
    }
    else 
#endif
    {
        int flag = 1;
        setsockopt(fs->listenFd, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag));
    }

    /* Bind it to the socket_addr */
    if (bind(fs->listenFd, fs->socket_addr, fs->socket_addr_len))
    {
        char port[11];

#ifdef WIN32
        errno = WSAGetLastError();
#endif
        ap_snprintf(port, sizeof(port), "port=%d", 
            ((struct sockaddr_in *)fs->socket_addr)->sin_port);

        ap_log_error(FCGI_LOG_CRIT_ERRNO, fcgi_apache_main_server,
            "FastCGI: can't create %sserver \"%s\": bind() failed [%s]", 
            (fs->directive == APP_CLASS_DYNAMIC) ? "(dynamic) " : "",
            fs->fs_path,
#ifndef WIN32
            (fs->socket_addr->sa_family == AF_UNIX) ?
                ((struct sockaddr_un *)fs->socket_addr)->sun_path :
#endif
                port);
    }

#ifndef WIN32
    /* Twiddle Unix socket permissions */
    else if (fs->socket_addr->sa_family == AF_UNIX
        && chmod(((struct sockaddr_un *)fs->socket_addr)->sun_path, S_IRUSR | S_IWUSR))
    {
        ap_log_error(FCGI_LOG_CRIT, fcgi_apache_main_server,
            "FastCGI: can't create %sserver \"%s\": chmod() of socket failed", 
            (fs->directive == APP_CLASS_DYNAMIC) ? "(dynamic) " : "",
            fs->fs_path);
    }
#endif

    /* Set to listen */
    else if (listen(fs->listenFd, fs->listenQueueDepth))
    {
#ifdef WIN32
        errno = WSAGetLastError();
#endif
        ap_log_error(FCGI_LOG_CRIT_ERRNO, fcgi_apache_main_server,
            "FastCGI: can't create %sserver \"%s\": listen() failed", 
            (fs->directive == APP_CLASS_DYNAMIC) ? "(dynamic) " : "",
            fs->fs_path);
    }
    else
    {
        return 0;
    }

    ap_pclosesocket(fcgi_config_pool, fs->listenFd);
    fs->listenFd = -1;
    return -2;
}

/*
 *----------------------------------------------------------------------
 *
 * pm_main
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
 *      Uses global variable fcgi_servers.
 *
 * Results:
 *      Does not return.
 *
 * Side effects:
 *      Described above.
 *
 *----------------------------------------------------------------------
 */
#ifndef WIN32
static int caughtSigTerm = FALSE;
static int caughtSigChld = FALSE;
static int caughtSigUsr2 = FALSE;

static void signal_handler(int signo)
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
    } else if(signo == SIGALRM) {
        caughtSigUsr2 = TRUE;
    }
}
#endif

/*
 *----------------------------------------------------------------------
 *
 * spawn_fs_process --
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

static pid_t spawn_fs_process(fcgi_server *fs, ServerProcess *process)
{
#ifndef WIN32
    pid_t child_pid;
    int i;
    char *dirName;
    char *dnEnd, *failedSysCall;

    child_pid = fork();
    if (child_pid) {
        return child_pid;
    }

    /* We're the child.  We're gonna exec() so pools don't matter. */

    dnEnd = strrchr(fs->fs_path, '/');
    if (dnEnd == NULL) {
        dirName = "./";
    } else {
        dirName = ap_pcalloc(fcgi_config_pool, dnEnd - fs->fs_path + 1);
        dirName = memcpy(dirName, fs->fs_path, dnEnd - fs->fs_path);
    }
    if (chdir(dirName) < 0) {
        failedSysCall = "chdir()";
        goto FailedSystemCallExit;
    }

#ifndef __EMX__
     /* OS/2 dosen't support nice() */
    if (fs->processPriority != 0) {
        if (nice(fs->processPriority) == -1) {
            failedSysCall = "nice()";
            goto FailedSystemCallExit;
        }
    }
#endif

    /* Open the listenFd on spec'd fd */
    if (fs->listenFd != FCGI_LISTENSOCK_FILENO)
        dup2(fs->listenFd, FCGI_LISTENSOCK_FILENO);

    /* Close all other open fds, except stdout/stderr.  Leave these two open so
     * FastCGI applications don't have to find and fix ALL 3rd party libs that
     * write to stdout/stderr inadvertantly.  For now, just leave 'em open to the
     * main server error_log - @@@ provide a directive control where this goes.
     */
    ap_error_log2stderr(fcgi_apache_main_server);
    dup2(STDERR_FILENO, STDOUT_FILENO);
    for (i = 0; i < FCGI_MAX_FD; i++) {
        if (i != FCGI_LISTENSOCK_FILENO && i != STDERR_FILENO && i != STDOUT_FILENO) {
            close(i);
        }
    }

    /* Ignore SIGPIPE by default rather than terminate.  The fs SHOULD
     * install its own handler. */
    signal(SIGPIPE, SIG_IGN);

    if (fcgi_wrapper && (fcgi_user_id != fs->uid || fcgi_group_id != fs->gid)) {
        char *shortName = strrchr(fs->fs_path, '/') + 1;

        /* Relinquish our root real uid powers */
        seteuid_root();
        setuid(ap_user_id);

        do {
            execle(fcgi_wrapper, fcgi_wrapper, fs->username, fs->group, shortName, NULL, fs->envp);
        } while (errno == EINTR);
    }
    else {
        do {
            execle(fs->fs_path, fs->fs_path, NULL, fs->envp);
        } while (errno == EINTR);
    }

    failedSysCall = "execle()";

FailedSystemCallExit:
    fprintf(stderr, "FastCGI: can't start server \"%s\" (pid %ld), %s failed: %s\n",
        fs->fs_path, (long) getpid(), failedSysCall, strerror(errno));
    exit(-1);

    /* avoid an irrelevant compiler warning */
    return(0);

#else

    /* Adapted from Apache's util_script.c ap_call_exec() */
    char *interpreter = NULL;
    char *quoted_filename;
    char *pCommand;
    char *pEnvBlock, *pNext;

    int i = 0;
    int iEnvBlockLen = 1;

    file_type_e fileType;

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    request_rec r;
    pid_t pid = -1;

    pool * tp = ap_make_sub_pool(fcgi_config_pool);

    HANDLE listen_handle;
    char * termination_env_string = NULL;

    process->terminationEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    SetHandleInformation(process->terminationEvent, HANDLE_FLAG_INHERIT, TRUE);
    
    termination_env_string = ap_psprintf(tp, 
        "_FCGI_SHUTDOWN_EVENT_=%ld", process->terminationEvent);
    
    if (fs->socket_path) 
    {
        SECURITY_ATTRIBUTES sa;

        sa.lpSecurityDescriptor = NULL;
        sa.bInheritHandle = TRUE;
        sa.nLength = sizeof(sa);

        listen_handle = CreateNamedPipe(fs->socket_path, 
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, &sa);

        if (listen_handle == INVALID_HANDLE_VALUE) 
        {
            ap_log_error(FCGI_LOG_CRIT, fcgi_apache_main_server,
                "FastCGI: can't exec server \"%s\", CreateNamedPipe() failed", fs->fs_path);
            exit(0);
        }

//        SetHandleInformation(listen_handle, HANDLE_FLAG_INHERIT, TRUE);
    }
    else 
    {
        listen_handle = (HANDLE) fs->listenFd;
    }

    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    memset(&r,  0, sizeof(r));

    // Can up a fake request to pass to ap_get_win32_interpreter()
    r.per_dir_config = fcgi_apache_main_server->lookup_defaults;
    r.server = fcgi_apache_main_server;
    r.filename = (char *) fs->fs_path;
    r.pool = tp;

    fileType = ap_get_win32_interpreter(&r, &interpreter);

    if (fileType == eFileTypeUNKNOWN) {
        ap_log_error(FCGI_LOG_ERR_NOERRNO, fcgi_apache_main_server,
            "FastCGI: %s is not executable; ensure interpreted scripts have "
            "\"#!\" as their first line", 
            fs->fs_path);
        ap_destroy_pool(tp);
        return (pid);
    }

    /*
     * We have the interpreter (if there is one) and we have 
     * the arguments (if there are any).
     * Build the command string to pass to CreateProcess. 
     */
    quoted_filename = ap_pstrcat(tp, "\"", fs->fs_path, "\"", NULL);
    if (interpreter && *interpreter) {
        pCommand = ap_pstrcat(tp, interpreter, " ", quoted_filename, NULL);
    }
    else {
        pCommand = quoted_filename;
    }

    /*
     * Make child process use hPipeOutputWrite as standard out,
     * and make sure it does not show on screen.
     */
    si.cb = sizeof(si);
    si.dwFlags     = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdInput   = listen_handle;

    // XXX These should be open to the error_log
    si.hStdOutput  = INVALID_HANDLE_VALUE;
    si.hStdError   = INVALID_HANDLE_VALUE;

    /*
     * Win32's CreateProcess call requires that the environment
     * be passed in an environment block, a null terminated block of
     * null terminated strings.
     * @todo we should store the env in this format for win32.
     */  
    while (fs->envp[i]) 
    {
        iEnvBlockLen += strlen(fs->envp[i]) + 1;
        i++;
    }

    iEnvBlockLen += strlen(termination_env_string) + 1;
    iEnvBlockLen += strlen(fs->mutex_env_string) + 1;

    pEnvBlock = (char *) ap_pcalloc(tp, iEnvBlockLen);

    i = 0;
    pNext = pEnvBlock;
    while (fs->envp[i]) 
    {
        strcpy(pNext, fs->envp[i]);
        pNext += strlen(pNext) + 1;
        i++;
    }

    strcpy(pNext, termination_env_string);
    pNext += strlen(pNext) + 1;
    strcpy(pNext, fs->mutex_env_string);
    
    if (CreateProcess(NULL, pCommand, NULL, NULL, TRUE, 
                      0,
                      pEnvBlock,
                      ap_make_dirstr_parent(tp, fs->fs_path),
                      &si, &pi)) 
    {
        /* Hack to get 16-bit CGI's working. It works for all the 
         * standard modules shipped with Apache. pi.dwProcessId is 0 
         * for 16-bit CGIs and all the Unix specific code that calls 
         * ap_call_exec interprets this as a failure case. And we can't 
         * use -1 either because it is mapped to 0 by the caller.
         */
        pid = (fileType == eFileTypeEXE16) ? -2 : pi.dwProcessId;

        process->handle = pi.hProcess;
        CloseHandle(pi.hThread);
    }

    if (fs->socket_path) 
    {
        CloseHandle(listen_handle);
    }

    ap_destroy_pool(tp);

    return pid;

#endif
}

#ifndef WIN32
static void reduce_privileges(void)
{
    char *name;

    if (geteuid() != 0)
        return;

#ifndef __EMX__
    /* Get username if passed as a uid */
    if (ap_user_name[0] == '#') {
        uid_t uid = atoi(&ap_user_name[1]);
        struct passwd *ent = getpwuid(uid);

        if (ent == NULL) {
            ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
                "FastCGI: process manager exiting, getpwuid(%u) couldn't determine user name, "
                "you probably need to modify the User directive", (unsigned)uid);
            exit(1);
        }
        name = ent->pw_name;
    }
    else
        name = ap_user_name;

    /* Change Group */
    if (setgid(ap_group_id) == -1) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
            "FastCGI: process manager exiting, setgid(%u) failed", (unsigned)ap_group_id);
        exit(1);
    }

    /* See Apache PR2580. Until its resolved, do it the same way CGI is done.. */

    /* Initialize supplementary groups */
    if (initgroups(name, ap_group_id) == -1) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
            "FastCGI: process manager exiting, initgroups(%s,%u) failed",
            name, (unsigned)ap_group_id);
        exit(1);
    }
#endif /* __EMX__ */

    /* Change User */
    if (fcgi_wrapper) {
        if (seteuid_user() == -1) {
            ap_log_error(FCGI_LOG_ALERT_NOERRNO, fcgi_apache_main_server,
                "FastCGI: process manager exiting, failed to reduce privileges");
            exit(1);
        }
    }
    else {
        if (setuid(ap_user_id) == -1) {
            ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
                "FastCGI: process manager exiting, setuid(%u) failed", (unsigned)ap_user_id);
            exit(1);
        }
    }
}

/*************
 * Change the name of this process - best we can easily.
 */
static void change_process_name(const char * const name)
{
    strncpy(ap_server_argv0, name, strlen(ap_server_argv0));
}
#endif

static void schedule_start(fcgi_server *s, int proc)
{
    /* If we've started one recently, don't register another */
    time_t time_passed = now - s->restartTime;

    if ((s->procs[proc].pid && (time_passed < (int) s->restartDelay))
        || ((s->procs[proc].pid == 0) && (time_passed < (int) s->initStartDelay)))
    {
        FCGIDBG6("ignore_job: slot=%d, pid=%ld, time_passed=%ld, initStartDelay=%ld, restartDelay=%ld", proc, s->procs[proc].pid, time_passed, s->initStartDelay, s->restartDelay);
        return;
    }

    FCGIDBG3("scheduling_start: %s (%d)", s->fs_path, proc);
    s->procs[proc].state = FCGI_START_STATE;
    if (proc == (int)dynamicMaxClassProcs - 1) {
        ap_log_error(FCGI_LOG_WARN_NOERRNO, fcgi_apache_main_server,
            "FastCGI: scheduled the %sstart of the last (dynamic) server "
            "\"%s\" process: reached dynamicMaxClassProcs (%d)",
            s->procs[proc].pid ? "re" : "", s->fs_path, dynamicMaxClassProcs);
    }
}

/*
 *----------------------------------------------------------------------
 *
 * dynamic_read_msgs
 *
 *      Removes the records written by request handlers and decodes them.
 *      We also update the data structures to reflect the changes.
 *
 *----------------------------------------------------------------------
 */

static void dynamic_read_msgs(int read_ready)
{
    fcgi_server *s;

#ifndef WIN32
    int rc;
    static int buflen = 0;
    static char buf[FCGI_MSGS_BUFSIZE + 1];
    char *ptr1, *ptr2, opcode;
    char execName[FCGI_MAXPATH + 1];
    char user[MAX_USER_NAME_LEN + 2];
    char group[MAX_GID_CHAR_LEN + 1];
    unsigned long q_usec = 0UL, req_usec = 0UL;
#else
    fcgi_pm_job *joblist = NULL;
    fcgi_pm_job *cjob = NULL;
#endif

    pool *sp, *tp;

#ifndef WIN32
    user[MAX_USER_NAME_LEN + 1] = group[MAX_GID_CHAR_LEN] = '\0';
#endif

    /*
     * To prevent the idle application from running indefinitely, we
     * check the timer and if it is expired, we recompute the values
     * for each running application class.  Then, when FCGI_REQUEST_COMPLETE_JOB
     * message is received, only updates are made to the data structures.
     */
    if (fcgi_dynamic_last_analyzed == 0) {
        fcgi_dynamic_last_analyzed = now;
    }
    if ((now - fcgi_dynamic_last_analyzed) >= (int)dynamicUpdateInterval) {
        for (s = fcgi_servers; s != NULL; s = s->next) {
            if (s->directive != APP_CLASS_DYNAMIC)
                break;

            /* Advance the last analyzed timestamp by the elapsed time since
             * it was last set. Round the increase down to the nearest
             * multiple of dynamicUpdateInterval */

            fcgi_dynamic_last_analyzed += (((long)(now-fcgi_dynamic_last_analyzed)/dynamicUpdateInterval)*dynamicUpdateInterval);
            s->smoothConnTime = (unsigned long) ((1.0-dynamicGain)*s->smoothConnTime + dynamicGain*s->totalConnTime);
            s->totalConnTime = 0UL;
            s->totalQueueTime = 0UL;
        }
    }

    if (read_ready <= 0) {
        return;
    }
    
#ifndef WIN32
    rc = read(fcgi_pm_pipe[0], (void *)(buf + buflen), FCGI_MSGS_BUFSIZE - buflen);
    if (rc <= 0) {
        if (!caughtSigTerm) {
            ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server, 
                "FastCGI: read() from pipe failed (%d)", rc);
            if (rc == 0) {
                ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server, 
                    "FastCGI: the PM is shutting down, Apache seems to have disappeared - bye");
                caughtSigTerm = TRUE;
            }
        }
        return;
    }
    buflen += rc;
    buf[buflen] = '\0';
#else
    if (ap_acquire_mutex(fcgi_dynamic_mbox_mutex) != MULTI_OK) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
            "FastCGI: Failed to aquire the dynamic mbox mutex!");
    }

    joblist = fcgi_dynamic_mbox;
    fcgi_dynamic_mbox = NULL;

    if (! ap_release_mutex(fcgi_dynamic_mbox_mutex)) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
            "FastCGI: Failed to release the dynamic mbox mutex!");
    }

    cjob = joblist;
#endif
    
    tp = ap_make_sub_pool(fcgi_config_pool);

#ifndef WIN32
    for (ptr1 = buf; ptr1; ptr1 = ptr2) {
        int scan_failed = 0;

        ptr2 = strchr(ptr1, '*');
        if (ptr2) {
            *ptr2++ = '\0';
        }
        else {
            break;
        }
        
        opcode = *ptr1;

        switch (opcode) 
        {
        case FCGI_SERVER_START_JOB:
        case FCGI_SERVER_RESTART_JOB:

            if (sscanf(ptr1, "%c %s %16s %15s",
                &opcode, execName, user, group) != 4)
            {
                scan_failed = 1;
            }
            break;

        case FCGI_REQUEST_TIMEOUT_JOB:

            if (sscanf(ptr1, "%c %s %16s %15s",
                &opcode, execName, user, group) != 4)
            {
                scan_failed = 1;
            }
            break;

        case FCGI_REQUEST_COMPLETE_JOB:

            if (sscanf(ptr1, "%c %s %16s %15s %lu %lu",
                &opcode, execName, user, group, &q_usec, &req_usec) != 6)
            {
                scan_failed = 1;
            }
            break;

        default:

            scan_failed = 1;
            break;
        }

        if (scan_failed) {
            ap_log_error(FCGI_LOG_ERR_NOERRNO, fcgi_apache_main_server,
                "FastCGI: bogus message, sscanf() failed: \"%s\"", ptr1);
            goto NextJob;
        }
#else
    /* Update data structures for processing */
    while (cjob != NULL) {
        joblist = cjob->next;
        FCGIDBG7("read_job: %c %s %s %s %lu %lu", cjob->id, cjob->fs_path, cjob->user, cjob->group, cjob->qsec, cjob->start_time);
#endif

#ifndef WIN32
        s = fcgi_util_fs_get(execName, user, group);
#else
        s = fcgi_util_fs_get(cjob->fs_path, cjob->user, cjob->group);
#endif

#ifndef WIN32
        if (s==NULL && opcode != FCGI_REQUEST_COMPLETE_JOB)
#else
        if (s==NULL && cjob->id != FCGI_REQUEST_COMPLETE_JOB)
#endif
        {
#ifdef WIN32
            HANDLE mutex = ap_create_mutex(NULL);
            
            SetHandleInformation(mutex, HANDLE_FLAG_INHERIT, TRUE);
#else
            int fd;
            const char *err;
#endif
            
            /* Create a perm subpool to hold the new server data,
             * we can destroy it if something doesn't pan out */
            sp = ap_make_sub_pool(fcgi_config_pool);

            /* Create a new "dynamic" server */
            s = fcgi_util_fs_new(sp);

            s->directive = APP_CLASS_DYNAMIC;
            s->restartDelay = dynamicRestartDelay;
            s->listenQueueDepth = dynamicListenQueueDepth;
            s->initStartDelay = dynamicInitStartDelay;
            s->envp = dynamicEnvp;
            s->flush = dynamicFlush;
            
#ifdef WIN32
            s->mutex_env_string = ap_psprintf(sp, "_FCGI_MUTEX_=%ld", mutex);
            s->fs_path = ap_pstrdup(sp, cjob->fs_path);
#else
            s->fs_path = ap_pstrdup(sp, execName);
#endif
            ap_getparents(s->fs_path);
            ap_no2slash(s->fs_path);
            s->procs = fcgi_util_fs_create_procs(sp, dynamicMaxClassProcs);

#ifndef WIN32
            /* Create socket file's path */
            s->socket_path = fcgi_util_socket_hash_filename(tp, execName, user, group);
            s->socket_path = fcgi_util_socket_make_path_absolute(sp, s->socket_path, 1);

            /* Create sockaddr, prealloc it so it won't get created in tp */
            s->socket_addr = ap_pcalloc(sp, sizeof(struct sockaddr_un));
            err = fcgi_util_socket_make_domain_addr(tp, (struct sockaddr_un **)&s->socket_addr,
                                          &s->socket_addr_len, s->socket_path);
            if (err) {
                ap_log_error(FCGI_LOG_CRIT, fcgi_apache_main_server,
                    "FastCGI: can't create (dynamic) server \"%s\": %s", execName, err);
                goto BagNewServer;
            }

            if (init_listen_sock(s)) {
                goto BagNewServer;
            }

            /* If a wrapper is being used, config user/group info */
            if (fcgi_wrapper) {
                if (user[0] == '~') {
                    /* its a user dir uri, the rest is a username, not a uid */
                    struct passwd *pw = getpwnam(&user[1]);

                    if (!pw) {
                        ap_log_error(FCGI_LOG_CRIT, fcgi_apache_main_server,
                            "FastCGI: can't create (dynamic) server \"%s\": can't get uid/gid for wrapper: getpwnam(%s) failed",
                            execName, &user[1]);
                        goto BagNewServer;
                    }
                    s->uid = pw->pw_uid;
                    s->user = ap_pstrdup(sp, user);
                    s->username = s->user;

                    s->gid = pw->pw_gid;
                    s->group = ap_psprintf(sp, "%ld", (long)s->gid);
                }
                else {
                    struct passwd *pw;

                    s->uid = (uid_t)atol(user);
                    pw = getpwuid(s->uid);
                    if (!pw) {
                        ap_log_error(FCGI_LOG_CRIT, fcgi_apache_main_server,
                            "FastCGI: can't create (dynamic) server \"%s\": can't get uid/gid for wrapper: getwpuid(%ld) failed",
                            execName, (long)s->uid);
                        goto BagNewServer;
                    }
                    s->user = ap_pstrdup(sp, user);
                    s->username = ap_pstrdup(sp, pw->pw_name);

                    s->gid = (gid_t)atol(group);
                    s->group = ap_pstrdup(sp, group);
                }
            }
#else
            /* Create socket file's path */
            s->socket_path = fcgi_util_socket_hash_filename(tp, cjob->fs_path, cjob->user, cjob->group);
            s->socket_path = fcgi_util_socket_make_path_absolute(sp, s->socket_path, 1);
            s->listenFd = 0;
#endif

            fcgi_util_fs_add(s);
        }
        else {
#ifndef WIN32
            if (opcode == FCGI_SERVER_RESTART_JOB) {
#else
            if (cjob->id==FCGI_SERVER_RESTART_JOB) {
#endif
                /* Check to see if the binary has changed.  If so,
                * kill the FCGI application processes, and
                * restart them.
                */
                struct stat stbuf;
                int i;

#ifndef WIN32
                if ((stat(execName, &stbuf)==0) &&
#else
                if ((stat(cjob->fs_path, &stbuf)==0) &&
#endif
                        (stbuf.st_mtime > s->restartTime)) {
                    /* kill old server(s) */
                    for (i = 0; i < dynamicMaxClassProcs; i++) {
                        if (s->procs[i].pid > 0) {
                            fcgi_kill(&s->procs[i], SIGTERM);
                        }
                    }

                    ap_log_error(FCGI_LOG_WARN_NOERRNO, fcgi_apache_main_server,
                                 "FastCGI: restarting server \"%s\" processes, newer version found",
#ifndef WIN32
                                 execName);
#else
                                 cjob->fs_path);
#endif
                }

                /* If dynamicAutoRestart, don't mark any new processes
                 * for  starting because we probably got the
                 * FCGI_SERVER_START_JOB due to dynamicAutoUpdate and the ProcMgr
                 * will be restarting all of those we just killed.
                 */
                if (dynamicAutoRestart)
                    goto NextJob;
            } 
#ifndef WIN32
            else if (opcode == FCGI_SERVER_START_JOB) {
#else
            else if (cjob->id==FCGI_SERVER_START_JOB) {
#endif
                /* we've been asked to start a process--only start
                * it if we're not already running at least one
                * instance.
                */
                int i;

                for (i = 0; i < dynamicMaxClassProcs; i++) {
                   if (s->procs[i].state == FCGI_RUNNING_STATE)
                      break;
                }
                /* if already running, don't start another one */
                if (i < dynamicMaxClassProcs) {
                    goto NextJob;
                }
            }
        }

#ifndef WIN32
        switch (opcode)
#else
        switch (cjob->id)
#endif
        {
            int i, start;

            case FCGI_SERVER_RESTART_JOB:

                start = FALSE;
                
                /* We just waxed 'em all.  Try to find an idle slot. */

                for (i = 0; i < dynamicMaxClassProcs; ++i)
                {
                    if (s->procs[i].state == FCGI_START_STATE
                        || s->procs[i].state == FCGI_RUNNING_STATE)
                    {
                        break;
                    }
                    else if (s->procs[i].state == FCGI_KILLED_STATE 
                        || s->procs[i].state == FCGI_READY_STATE)
                    {
                        start = TRUE;
                        break;
                    }
                }

                /* Nope, just use the first slot */
                if (i == dynamicMaxClassProcs)
                {
                    start = TRUE;
                    i = 0;
                }
                
                if (start)
                {
                    schedule_start(s, i);
                }
                        
                break;

            case FCGI_SERVER_START_JOB:
            case FCGI_REQUEST_TIMEOUT_JOB:

                if ((fcgi_dynamic_total_proc_count + 1) > (int) dynamicMaxProcs) {
                    /*
                     * Extra instances should have been
                     * terminated beforehand, probably need
                     * to increase ProcessSlack parameter
                     */
                    ap_log_error(FCGI_LOG_WARN_NOERRNO, fcgi_apache_main_server,
                        "FastCGI: can't schedule the start of another (dynamic) server \"%s\" process: "
                        "exceeded dynamicMaxProcs (%d)", s->fs_path, dynamicMaxProcs);
                    goto NextJob;
                }

                /* find next free slot */
                for (i = 0; i < dynamicMaxClassProcs; i++) 
                {
                    if (s->procs[i].state == FCGI_START_STATE) 
                    {
                        FCGIDBG2("ignore_job: slot (%d) is already scheduled for starting", i);
                        break;
                    }
                    else if (s->procs[i].state == FCGI_RUNNING_STATE)
                    {
                        continue;
                    }
                        
                    schedule_start(s, i);
                    break;
                }

#ifdef FCGI_DEBUG
                if (i >= dynamicMaxClassProcs) {
                    FCGIDBG1("ignore_job: slots are max'd");
                }
#endif
                break;
            case FCGI_REQUEST_COMPLETE_JOB:
                /* only record stats if we have a structure */
                if (s) {
#ifndef WIN32
                    s->totalConnTime += req_usec;
                    s->totalQueueTime += q_usec;
#else
                    s->totalConnTime += cjob->start_time;
                    s->totalQueueTime += cjob->qsec;
#endif
                }
                break;
        }

NextJob:

#ifdef WIN32
        /* Cleanup job data */
        free(cjob->fs_path);
        free(cjob->user);
        free(cjob->group);
        free(cjob);
        cjob = joblist;
#endif

        continue;

BagNewServer:
        ap_destroy_pool(sp);

#ifdef WIN32
    free(cjob->fs_path);
    free(cjob);
    cjob = joblist;
#endif
    }

#ifndef WIN32
    if (ptr1 == buf) {
        ap_log_error(FCGI_LOG_ERR_NOERRNO, fcgi_apache_main_server,
            "FastCGI: really bogus message: \"%s\"", ptr1);
        ptr1 += strlen(buf);
    }
            
    buflen -= ptr1 - buf;
    if (buflen) {
        memmove(buf, ptr1, buflen);
    }
#endif

    ap_destroy_pool(tp);
}

/*
 *----------------------------------------------------------------------
 *
 * dynamic_kill_idle_fs_procs
 *
 *      Implement a kill policy for the dynamic FastCGI applications.
 *      We also update the data structures to reflect the changes.
 *
 * Side effects:
 *      Processes are marked for deletion possibly killed.
 *
 *----------------------------------------------------------------------
 */
static void dynamic_kill_idle_fs_procs(void)
{
    fcgi_server *s;
    int victims = 0;

    for (s = fcgi_servers;  s != NULL; s = s->next) 
    {
        /* 
         * server's smoothed running time, or if that's 0, the current total 
         */
        unsigned long connTime;  
        
        /* 
         * maximum number of microseconds that all of a server's running 
         * processes together could have spent running since the last check 
         */
        unsigned long totalTime;  

        /* 
         * percentage, 0-100, of totalTime that the processes actually used 
         */
        int loadFactor;        

        int i;
        
        if (s->directive != APP_CLASS_DYNAMIC || s->numProcesses == 0)
        {
            continue;
        }

        connTime = s->smoothConnTime ? s->smoothConnTime : s->totalConnTime;
        totalTime = s->numProcesses * (now - fcgi_dynamic_epoch) * 1000000 + 1;

        loadFactor = 100 * connTime / totalTime;

        if (s->numProcesses == 1)
        {
            if (loadFactor >= dynamicThreshold1)
            {
                continue;
            }
        }
        else
        {
            int load = s->numProcesses / (s->numProcesses - 1) * loadFactor;
            
            if (load >= dynamicThresholdN)
            {
                continue;
            }
        }

        /*
         * Run through the procs to see if we can get away w/o waxing one.
         */
        for (i = 0; i < dynamicMaxClassProcs; ++i) 
        {
            if (s->procs[i].state == FCGI_START_STATE) 
            {
                s->procs[i].state = FCGI_READY_STATE;
                break;
            }
            else if (s->procs[i].state == FCGI_VICTIM_STATE) 
            {
                break;
            }
        }

        if (i < dynamicMaxClassProcs)
        {
            continue;
        }

        for (i = 0; i < dynamicMaxClassProcs; ++i) 
        {
            if (s->procs[i].state != FCGI_RUNNING_STATE) 
            {
                continue;
            }

            ap_log_error(FCGI_LOG_WARN_NOERRNO, fcgi_apache_main_server,
                "FastCGI: (dynamic) server \"%s\" (pid %ld) termination signaled",
                s->fs_path, s->procs[i].pid);

            fcgi_kill(&s->procs[i], SIGTERM);
            
            victims++;
            break;
        }

        /* 
         * If the number of non-victims is less than or equal to
         * the minimum that may be running without being killed off,
         * don't select any more victims. 
         */
        if (fcgi_dynamic_total_proc_count - victims <= dynamicMinProcs) 
        {
            break;
        }
    }
}

#ifdef WIN32

// This is a little bogus, there's gotta be a better way to do this
// Can we use WaitForMultipleObjects()
#define FCGI_PROC_WAIT_TIME 100

void child_wait_thread(void *dummy) {
    fcgi_server *s;
    DWORD dwRet = WAIT_TIMEOUT;
    int numChildren;
    int i;
    int waited;

    while (!bTimeToDie) {
        waited = 0;

        for (s = fcgi_servers; s != NULL; s = s->next) {
            if (s->directive == APP_CLASS_EXTERNAL || s->listenFd < 0) {
                continue;
            }
            if (s->directive == APP_CLASS_DYNAMIC) {
                numChildren = dynamicMaxClassProcs;
            }
            else {
                numChildren = s->numProcesses;
            }

            for (i=0; i < numChildren; i++) {
                if (s->procs[i].handle != INVALID_HANDLE_VALUE) 
                {
                    DWORD exitStatus = 0;

                    /* timeout is currently set for 100 miliecond */ 
                    /* it may need t longer or user customizable */
                    dwRet = WaitForSingleObject(s->procs[i].handle, FCGI_PROC_WAIT_TIME);

                    waited = 1;

                    if (dwRet != WAIT_TIMEOUT && dwRet != WAIT_FAILED) {
                        /* a child fs has died */
                        /* mark the child as dead */

                        if (s->directive == APP_CLASS_STANDARD) {
                            /* restart static app */
                            s->procs[i].state = FCGI_START_STATE;
                            s->numFailures++;
                        }
                        else {
                            s->numProcesses--;
                            fcgi_dynamic_total_proc_count--;
                            FCGIDBG2("-- fcgi_dynamic_total_proc_count=%d", fcgi_dynamic_total_proc_count);

                            if (s->procs[i].state == FCGI_VICTIM_STATE) {
                                s->procs[i].state = FCGI_KILLED_STATE;
                            }
                            else {
                                /* dynamic app shouldn't have died or dynamicAutoUpdate killed it*/
                                s->numFailures++;

                                if (dynamicAutoRestart || (s->numProcesses <= 0 && dynamicThreshold1 == 0)) {
                                    s->procs[i].state = FCGI_START_STATE;
                                }
                                else {
                                    s->procs[i].state = FCGI_READY_STATE;
                                }
                            }
                        }

                        GetExitCodeProcess(s->procs[i].handle, &exitStatus);

                        ap_log_error(FCGI_LOG_WARN_NOERRNO, fcgi_apache_main_server,
                            "FastCGI:%s server \"%s\" (pid %d) terminated with exit with status '%d'",
                            (s->directive == APP_CLASS_DYNAMIC) ? " (dynamic)" : "",
                            s->fs_path, s->procs[i].pid, exitStatus);

                        CloseHandle(s->procs[i].handle);
                        s->procs[i].handle = INVALID_HANDLE_VALUE;
                        s->procs[i].pid = -1;

                        /* wake up the main thread */
                        SetEvent(fcgi_event_handles[WAKE_EVENT]);
                    }
                }
            }
        }
        Sleep(waited ? 0 : FCGI_PROC_WAIT_TIME);
    }
}
#endif

#ifndef WIN32
static void setup_signals(void)
{
    sigset_t mask;
    struct sigaction sa;

    /* Ignore USR2 */
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR2);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    
    /* Setup handlers */

    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
        "sigaction(SIGTERM) failed");
    }
    /* httpd restart */
    if (sigaction(SIGHUP, &sa, NULL) < 0) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
        "sigaction(SIGHUP) failed");
    }
    /* httpd graceful restart */
    if (sigaction(SIGUSR1, &sa, NULL) < 0) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
        "sigaction(SIGUSR1) failed");
    }
    /* read messages from request handlers - kill interval expired */
    if (sigaction(SIGALRM, &sa, NULL) < 0) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
        "sigaction(SIGALRM) failed");
    }
    if (sigaction(SIGCHLD, &sa, NULL) < 0) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
        "sigaction(SIGCHLD) failed");
    }
}
#endif

#ifndef WIN32
int fcgi_pm_main(void *dummy, child_info *info)
#else
void fcgi_pm_main(void *dummy)
#endif
{
    fcgi_server *s;
    unsigned int i;
    int read_ready = 0;
    int alarmLeft = 0;

#ifdef WIN32
    DWORD dwRet;
    int first_time = 1;
    HANDLE wait_thread = INVALID_HANDLE_VALUE;
#else
    int callWaitPid, callDynamicProcs;
#endif

#ifdef WIN32
    // Add SystemRoot to the dynamic environment
    char ** envp = dynamicEnvp;
    for (i = 0; *envp; ++i) {
        ++envp;
    }
    fcgi_config_set_env_var(fcgi_config_pool, dynamicEnvp, &i, "SystemRoot");

#else
    reduce_privileges();

    close(fcgi_pm_pipe[1]);
    change_process_name("fcgi-pm");
    setup_signals();

    if (fcgi_wrapper) {
        ap_log_error(FCGI_LOG_NOTICE_NOERRNO, fcgi_apache_main_server,
            "FastCGI: wrapper mechanism enabled (wrapper: %s)", fcgi_wrapper);
    }
#endif

    /* Initialize AppClass */
    for (s = fcgi_servers; s != NULL; s = s->next) 
    {
        if (s->directive != APP_CLASS_STANDARD)
            continue;

#ifdef WIN32
        if (s->socket_path)
            s->listenFd = 0;
#endif

        for (i = 0; i < s->numProcesses; ++i) 
            s->procs[i].state = FCGI_START_STATE;
    }

#ifdef WIN32
    ap_log_error(FCGI_LOG_NOTICE_NOERRNO, fcgi_apache_main_server,
        "FastCGI: process manager initialized");
#else
    ap_log_error(FCGI_LOG_NOTICE_NOERRNO, fcgi_apache_main_server,
        "FastCGI: process manager initialized (pid %ld)", (long)getpid());
#endif

    now = time(NULL);

    /*
     * Loop until SIGTERM
     */
    for (;;) {
        int sleepSeconds = min(dynamicKillInterval, dynamicUpdateInterval);
#ifdef WIN32
        time_t expire;
#else
        pid_t childPid;
        int waitStatus;
#endif
        unsigned int numChildren;

        /*
         * If we came out of sigsuspend() for any reason other than
         * SIGALRM, pick up where we left off.
         */
        if (alarmLeft)
            sleepSeconds = alarmLeft;

        /*
         * Examine each configured AppClass for a process that needs
         * starting.  Compute the earliest time when the start should
         * be attempted, starting it now if the time has passed.  Also,
         * remember that we do NOT need to restart externally managed
         * FastCGI applications.
         */
        for (s = fcgi_servers; s != NULL; s = s->next) 
        {
            if (s->directive == APP_CLASS_EXTERNAL)
                continue;

            numChildren = (s->directive == APP_CLASS_DYNAMIC) 
                ? dynamicMaxClassProcs 
                : s->numProcesses;

            for (i = 0; i < numChildren; ++i) 
            {
                if (s->procs[i].pid <= 0 && s->procs[i].state == FCGI_START_STATE)
                {
                    int restart = (s->procs[i].pid < 0);
                    time_t restartTime = s->restartTime;
                    
                    restartTime += (restart) ? s->restartDelay : s->initStartDelay;

                    if (restartTime <= now) 
                    {
                        if (s->listenFd < 0 && init_listen_sock(s)) 
                        {
                            if (sleepSeconds > s->initStartDelay)
                                sleepSeconds = s->initStartDelay;
                            break;
                        }
#ifndef WIN32
                        if (caughtSigTerm) {
                            goto ProcessSigTerm;
                        }
#endif
                        s->procs[i].pid = spawn_fs_process(s, &s->procs[i]);
                        if (s->procs[i].pid <= 0) {
                            ap_log_error(FCGI_LOG_CRIT, fcgi_apache_main_server,
                                "FastCGI: can't start%s server \"%s\": spawn_fs_process() failed",
                                (s->directive == APP_CLASS_DYNAMIC) ? " (dynamic)" : "",
                                s->fs_path);

                            sleepSeconds = min(sleepSeconds,
                                max((int) s->restartDelay, FCGI_MIN_EXEC_RETRY_DELAY));

                            ap_assert(s->procs[i].pid < 0);
                            break;
                        }

                        s->restartTime = now;
                        
                        if (s->directive == APP_CLASS_DYNAMIC) {
                            s->numProcesses++;
                            fcgi_dynamic_total_proc_count++;
                            FCGIDBG2("++ fcgi_dynamic_total_proc_count=%d", fcgi_dynamic_total_proc_count);
                        }

                        s->procs[i].state = FCGI_RUNNING_STATE;

                        if (restart)
                            s->numRestarts++;

                        if (fcgi_wrapper) {
                            ap_log_error(FCGI_LOG_WARN_NOERRNO, fcgi_apache_main_server,
                                "FastCGI:%s server \"%s\" (uid %ld, gid %ld) %sstarted (pid %ld)",
                                (s->directive == APP_CLASS_DYNAMIC) ? " (dynamic)" : "",
                                s->fs_path, (long)s->uid, (long)s->gid,
                                restart ? "re" : "", (long)s->procs[i].pid);
                        }
                        else {
                            ap_log_error(FCGI_LOG_WARN_NOERRNO, fcgi_apache_main_server,
                                "FastCGI:%s server \"%s\" %sstarted (pid %ld)",
                                (s->directive == APP_CLASS_DYNAMIC) ? " (dynamic)" : "",
                                s->fs_path, restart ? "re" : "", (long)s->procs[i].pid);
                        }
                        ap_assert(s->procs[i].pid > 0);
                    } else {
                        sleepSeconds = min(sleepSeconds, restartTime - now);
                    }
                }
            }
        }

#ifndef WIN32
        if(caughtSigTerm) {
            goto ProcessSigTerm;
        }
        if((!caughtSigChld) && (!caughtSigUsr2)) {
            fd_set rfds;

            alarm(sleepSeconds);

            FD_ZERO(&rfds);
            FD_SET(fcgi_pm_pipe[0], &rfds);
            read_ready = ap_select(fcgi_pm_pipe[0] + 1, &rfds, NULL, NULL, NULL);

            alarmLeft = alarm(0);
        }
        callWaitPid = caughtSigChld;
        caughtSigChld = FALSE;
        callDynamicProcs = caughtSigUsr2;
        caughtSigUsr2 = FALSE;

        now = time(NULL);

        /*
         * Dynamic fcgi process management
         */
        if((callDynamicProcs) || (!callWaitPid)) {
            dynamic_read_msgs(read_ready);
            if(fcgi_dynamic_epoch == 0) {
                fcgi_dynamic_epoch = now;
            }
            if(((long)(now-fcgi_dynamic_epoch)>=dynamicKillInterval) ||
                    ((fcgi_dynamic_total_proc_count+dynamicProcessSlack)>=dynamicMaxProcs)) {
                dynamic_kill_idle_fs_procs();
                fcgi_dynamic_epoch = now;
            }
        }

        if(!callWaitPid) {
            continue;
        }

        /* We've caught SIGCHLD, so find out who it was using waitpid,
         * write a log message and update its data structure. */

        for (;;) {
            if (caughtSigTerm)
                goto ProcessSigTerm;

            childPid = waitpid(-1, &waitStatus, WNOHANG);
            
            if (childPid == -1 || childPid == 0)
                break;

            for (s = fcgi_servers; s != NULL; s = s->next) {
                if (s->directive == APP_CLASS_EXTERNAL)
                    continue;

                if (s->directive == APP_CLASS_DYNAMIC)
                    numChildren = dynamicMaxClassProcs;
                else
                    numChildren = s->numProcesses;

                for (i = 0; i < numChildren; i++) {
                    if (s->procs[i].pid == childPid)
                        goto ChildFound;
                }
            }

            /* TODO: print something about this unknown child */
            continue;

ChildFound:
            s->procs[i].pid = -1;

            if (s->directive == APP_CLASS_STANDARD) {
                /* Always restart static apps */
                s->procs[i].state = FCGI_START_STATE;
                s->numFailures++;
            }
            else {
                s->numProcesses--;
                fcgi_dynamic_total_proc_count--;

                if (s->procs[i].state == FCGI_VICTIM_STATE) {
                    s->procs[i].state = FCGI_KILLED_STATE;
                }
                else {
                    /* A dynamic app died or exited without provocation from the PM */
                    s->numFailures++;

                    if (dynamicAutoRestart || (s->numProcesses <= 0 && dynamicThreshold1 == 0))
                        s->procs[i].state = FCGI_START_STATE;
                    else
                        s->procs[i].state = FCGI_READY_STATE;
                }
            }

            if (WIFEXITED(waitStatus)) {
                ap_log_error(FCGI_LOG_WARN_NOERRNO, fcgi_apache_main_server,
                    "FastCGI:%s server \"%s\" (pid %d) terminated by calling exit with status '%d'",
                    (s->directive == APP_CLASS_DYNAMIC) ? " (dynamic)" : "",
                    s->fs_path, (int)childPid, WEXITSTATUS(waitStatus));
            }
            else if (WIFSIGNALED(waitStatus)) {
                ap_log_error(FCGI_LOG_WARN_NOERRNO, fcgi_apache_main_server,
                    "FastCGI:%s server \"%s\" (pid %d) terminated due to uncaught signal '%d' (%s)%s",
                    (s->directive == APP_CLASS_DYNAMIC) ? " (dynamic)" : "",
                    s->fs_path, (int)childPid, WTERMSIG(waitStatus), SYS_SIGLIST[WTERMSIG(waitStatus)],
#ifdef WCOREDUMP
                    WCOREDUMP(waitStatus) ? ", a core file may have been generated" : "");
#else
                    "");
#endif
            }
            else if (WIFSTOPPED(waitStatus)) {
                ap_log_error(FCGI_LOG_WARN_NOERRNO, fcgi_apache_main_server,
                    "FastCGI:%s server \"%s\" (pid %d) stopped due to uncaught signal '%d' (%s)",
                    (s->directive == APP_CLASS_DYNAMIC) ? " (dynamic)" : "",
                    s->fs_path, (int)childPid, WTERMSIG(waitStatus), SYS_SIGLIST[WTERMSIG(waitStatus)]);
            }
        } /* for (;;), waitpid() */
#else
        if (first_time) {
            /* Start the child wait thread */
            wait_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)child_wait_thread, NULL, 0, NULL);
            first_time = 0;
        }

        /* wait for an event to occur or timer expires */
        expire = time(NULL) + sleepSeconds;
        dwRet = WaitForMultipleObjects(3, (HANDLE *) fcgi_event_handles, FALSE, sleepSeconds * 1000);

        if (dwRet == WAIT_FAILED) {
            /* There is something seriously wrong here */
            ap_log_error(FCGI_LOG_CRIT, fcgi_apache_main_server,
                "FastCGI: WaitForMultipleObjects() failed on event handles -- pm is shuting down");
                bTimeToDie = TRUE;
        }

        if (dwRet != WAIT_TIMEOUT) {
           now = time(NULL);

           if (now < expire)
               alarmLeft = expire - now;
        }

        /*
         * Dynamic fcgi process management
         */
        if ((dwRet == MBOX_EVENT) || (dwRet == WAIT_TIMEOUT)) {
            if (dwRet == MBOX_EVENT) {
                read_ready = 1;    
            }

            now = time(NULL);

            dynamic_read_msgs(read_ready);

            if(fcgi_dynamic_epoch == 0) {
                fcgi_dynamic_epoch = now;
            }

            if (((long)(now-fcgi_dynamic_epoch) >= (int)dynamicKillInterval) ||
               ((fcgi_dynamic_total_proc_count+dynamicProcessSlack) >= dynamicMaxProcs)) {
                dynamic_kill_idle_fs_procs();
                fcgi_dynamic_epoch = now;
            }
            read_ready = 0;
        }
        else if (dwRet == WAKE_EVENT) {
            continue;
        }
        else if (dwRet == TERM_EVENT) {
            ap_log_error(FCGI_LOG_INFO_NOERRNO, fcgi_apache_main_server, 
                         "FastCGI: Termination event received process manager shutting down");
            bTimeToDie = TRUE;

            dwRet = WaitForSingleObject(wait_thread, INFINITE);
            goto ProcessSigTerm;
        }
        else {
            // Have an received an unknown event - should not happen
            ap_log_error(FCGI_LOG_CRIT, fcgi_apache_main_server,
                "FastCGI: WaitForMultipleobjects() return an unrecognized event");
            bTimeToDie = TRUE;
            dwRet = WaitForSingleObject(wait_thread, INFINITE);
            goto ProcessSigTerm;
        }
#endif
    } /* for (;;), the whole shoot'n match */

ProcessSigTerm:
    /*
     * Kill off the children, then exit.
     */
    shutdown_all();

#ifdef WIN32
    return;
#else
    exit(0);
#endif
}

#ifdef WIN32
int fcgi_pm_add_job(fcgi_pm_job *new_job) {

    if (new_job == NULL)
        return 0;

    if (ap_acquire_mutex(fcgi_dynamic_mbox_mutex) != MULTI_OK) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
            "FastCGI: Failed to aquire the dynamic mbox mutex!");
    }

    new_job->next = fcgi_dynamic_mbox;
    fcgi_dynamic_mbox = new_job;

    if (! ap_release_mutex(fcgi_dynamic_mbox_mutex)) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
            "FastCGI: Failed to release the dynamic mbox mutex!");
    }

    return 1;
}
#endif
