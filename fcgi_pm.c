/*
 * $Id: fcgi_pm.c,v 1.3 1999/02/21 01:19:55 roberts Exp $
 */

#include "fcgi.h"

static int fcgi_dynamic_total_proc_count = 0;    /* number of running apps */
static time_t fcgi_dynamic_epoch = 0;            /* last time kill_procs was
                                                  * invoked by process mgr */
static time_t fcgi_dynamic_last_analyzed = 0;    /* last time calculation was
                                                  * made for the dynamic procs*/

/* Information about a process we are doing a blocking kill of.  */
struct FuncData {
    const char *lockFileName;    /* name of the lock file to lock */
    pid_t pid;                   /* process to issue SIGTERM to   */
};

/*******************************************************************************
 * Send SIGTERM to each process in the server class, remove socket and lock
 * file if appropriate.  Currently this is only called when the PM is shutting
 * down and thus memory isn't freed and sockets and files aren't closed.
 */
static void kill_fs_procs(pool *p, fcgi_server *s)
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
        const char *lockFileName = fcgi_util_socket_get_lock_filename(p, s->socket_path);

        if (unlink(lockFileName) != 0) {
            ap_log_error(FCGI_LOG_ERR, fcgi_apache_main_server, 
                "FastCGI: unlink() failed to remove lock file \"%s\" for (dynamic) server \"%s\"",
                lockFileName, s->fs_path);
        }
    }

    /* Remove the socket file */
    if (s->socket_path != NULL && s->directive != APP_CLASS_EXTERNAL) {
        if (unlink(s->socket_path) != 0) {
            ap_log_error(FCGI_LOG_ERR, fcgi_apache_main_server, 
                "FastCGI: unlink() failed to remove socket file \"%s\" for%s server \"%s\"",
                s->socket_path, 
                (s->directive == APP_CLASS_DYNAMIC) ? " (dynamic)" : "", s->fs_path);
        }
    }
    fcgi_servers = s->next;
}

/*******************************************************************************
 * Bind an address to a socket and set it to listen for incoming connects.
 * The error messages are allocated from the pool p, use temp storage.
 * Don't forget to close the socket, if an error occurs.
 */
static const char *bind_n_listen(pool *p, struct sockaddr *socket_addr,
        int socket_addr_len, int backlog, int sock)
{
    if (socket_addr->sa_family == AF_UNIX) {
        /* Remove any existing socket file.. just in case */
        unlink(((struct sockaddr_un *)socket_addr)->sun_path);
    } else {
        int flag = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag));
    }

    /* Bind it to the socket_addr */
    if (bind(sock, socket_addr, socket_addr_len) != 0)
        return ap_pstrcat(p, "bind() failed: ", strerror(errno), NULL);

    /* Twiddle ownership and permissions */
    if (socket_addr->sa_family == AF_UNIX) {
#ifndef __EMX__
        /* If we're root, we're gonna setuid/setgid, so we need to chown */
        if (geteuid() == 0 &&
                chown(((struct sockaddr_un *)socket_addr)->sun_path, 
                      ap_user_id, ap_group_id) != 0)
            return ap_pstrcat(p, "chown() of socket failed: ", strerror(errno), NULL);
#endif
        if (chmod(((struct sockaddr_un *)socket_addr)->sun_path,
                  S_IRUSR | S_IWUSR) != 0)
            return ap_pstrcat(p, "chmod() of socket failed: ", strerror(errno), NULL);
    }

    /* Set to listen */
    if (listen(sock, backlog) != 0)
        return ap_pstrcat(p, "listen() failed: ", strerror(errno), NULL);

    return NULL;
}

/*
 *----------------------------------------------------------------------
 *
 * dynamic_blocking_kill
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
static void dynamic_blocking_kill(void *data)
{
    struct FuncData *funcData = (struct FuncData *)data;
    int lockFd;

    ap_assert(funcData->lockFileName);
    if ((lockFd = open(funcData->lockFileName, O_RDWR)) < 0) {
        /* There is something terribly wrong here */
    } else {
        if (fcgi_wait_for_shared_write_lock(lockFd) < 0) {
            /* This is a major problem */
        } else {
            kill(funcData->pid, SIGTERM);
        }
    }
    /* exit() may flush stdio buffers inherited from the parent. */
    _exit(0);
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
static int caughtSigTerm = FALSE;
static int caughtSigChld = FALSE;
static int caughtSigUsr2 = FALSE;
static sigset_t signalsToBlock;

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
    } else if(signo == SIGUSR2 || signo == SIGALRM) {
        caughtSigUsr2 = TRUE;
    }
}

static int caught_sigterm(void)
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

static int spawn_fs_process(
        pid_t *childPid,
        int listenFd,
        int priority,
        const char *programName,
        const char **envPtr,
        const char *user,
        const char *group)
{
    int i;
    char *dirName;
    char *dnEnd, *failedSysCall;

    *childPid = fork();
    if (*childPid < 0)
        return -1;
    
    if (*childPid != 0)
        return 0;

    /* We're the child.  We're gonna exec() so pools don't matter. */

    dnEnd = strrchr(programName, '/');
    if (dnEnd == NULL) {
        dirName = "./";
    } else {
        dirName = ap_pcalloc(fcgi_config_pool, dnEnd - programName + 1);
        dirName = memcpy(dirName, programName, dnEnd - programName);
    }
    if (chdir(dirName) < 0) {
        failedSysCall = "chdir()";
        goto FailedSystemCallExit;
    }

#ifndef __EMX__
     /* OS/2 dosen't support nice() */
    if (priority != 0) {
        if (nice(priority) == -1) {
            failedSysCall = "nice()";
            goto FailedSystemCallExit;
        }
    }
#endif

    /* Open the listenFd on spec'd fd */
    if (listenFd != FCGI_LISTENSOCK_FILENO)
        dup2(listenFd, FCGI_LISTENSOCK_FILENO);
    
    /* Close any other open fds */    
    for (i = 0; i < MAX_OPEN_FDS; i++) {
        if (i != FCGI_LISTENSOCK_FILENO)
            close(i);
    }
    
    /* Ignore SIGPIPE by default rather than terminate.  The fs SHOULD 
     * install its own handler. */
    signal(SIGPIPE, SIG_IGN);

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

    failedSysCall = "execle()";

    /* We had to close all files but the FCGI listener socket in order to
     * exec the application.  So we must reopen the log file. */
    ap_open_logs(fcgi_apache_main_server, fcgi_config_pool);
    
FailedSystemCallExit:
    ap_log_error(FCGI_LOG_ERR, fcgi_apache_main_server,
        "FastCGI: can't start server \"%s\" (pid %ld), %s failed",
        programName, (long) getpid(), failedSysCall);
    exit(-1);
    
    /* avoid an irrelevant compiler warning */
    return(0);          
}

static void reduce_priveleges()
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

#ifdef MULTIPLE_GROUPS
    /* Initialize supplementary groups */
    if (initgroups(name, ap_group_id) == -1) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
            "FastCGI: process manager exiting, initgroups(%s,%u) failed", 
            name, (unsigned)ap_group_id);
        exit(1);
    }

    /* Based on Apache 1.3.0 main/util.c... */
#elif !defined(QNX) && !defined(MPE) && !defined(BEOS) && !defined(_OSD_POSIX)
    /* QNX, MPE and BeOS do not appear to support supplementary groups. */

    if (setgroups(1, &ap_group_id) == -1) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
            "FastCGI: process manager exiting, setgroups(%u) failed", (unsigned)ap_group_id);
        exit(1);
    }
#endif
#endif

    /* Change real, effective, and saved UserId */
    if (setuid(ap_user_id) == -1) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server, 
            "FastCGI: process manager exiting, setuid(%u) failed", (unsigned)ap_user_id);
        exit(1);
    }
}

/*************
 * Change the name of this process - best we can easily.
 */
static void change_process_name(const char * const name)
{
    strncpy(ap_server_argv0, name, strlen(ap_server_argv0));
}

/*
 *----------------------------------------------------------------------
 *
 * dynamic_read_mbox
 *
 *      Removes the records from the fcgi_dynamic_mbox and decodes them.
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

static int dynamic_read_mbox(void)
{
    fcgi_server *s;
    struct stat statbuf;
    int recs = -1, fd;
    char *buf=NULL, opcode;
    char *ptr1=NULL, *ptr2=NULL;
    char execName[MAX_PROCMGR_RECORD_LEN];
    char user[MAX_USER_NAME_LEN + 2];
    char group[MAX_GID_CHAR_LEN + 1];
    unsigned long qsec = 0, start_time = 0; /* microseconds spent waiting for the
                                             * application, and spent using it */
    time_t now = time(NULL);
    pool *sp;
    pool * const tp = ap_make_sub_pool(fcgi_config_pool);

    user[MAX_USER_NAME_LEN + 1] = group[MAX_GID_CHAR_LEN] = '\0';

    /* Obtain the data from the fcgi_dynamic_mbox file */
    if ((fd = ap_popenf(tp, fcgi_dynamic_mbox, O_RDWR, S_IRUSR | S_IWUSR)) < 0) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server, 
            "FastCGI: openf() of fcgi_dynamic_mbox \"%s\" failed", fcgi_dynamic_mbox);
        goto CleanupReturn;
    }
    fcgi_wait_for_shared_write_lock(fd);
    if (fstat(fd, &statbuf) < 0) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server, 
            "FastCGI: fstat() of fcgi_dynamic_mbox \"%s\" failed", fcgi_dynamic_mbox);
        goto NothingToDo;
    }
    buf = ap_pcalloc(tp, statbuf.st_size + 1);
    if (statbuf.st_size==0) {
        recs = 0;
        goto NothingToDo;
    }
    if (read(fd, (void *)buf, statbuf.st_size) < statbuf.st_size) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server, 
            "FastCGI: read() from fcgi_dynamic_mbox \"%s\" failed", fcgi_dynamic_mbox);
        goto NothingToDo;
    }
    if (ftruncate(fd, 0) < 0) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server, 
            "FastCGI: ftruncate() of fcgi_dynamic_mbox \"%s\" failed", fcgi_dynamic_mbox);
        goto NothingToDo;
    }

    recs = 1;

NothingToDo:
    ap_pclosef(tp, fd);
    if (recs<0) {
        goto CleanupReturn;
    }

    /*
     * To prevent the idle application from running indefinitely, we
     * check the timer and if it is expired, we recompute the values
     * for each running application class.  Then, when REQ_COMPLETE
     * message is recieved, only updates are made to the data structures.
     */
    if (fcgi_dynamic_last_analyzed == 0) {
        fcgi_dynamic_last_analyzed = now;
    }
    if ((long)(now - fcgi_dynamic_last_analyzed) >= dynamicUpdateInterval) {
        for (s = fcgi_servers; s != NULL; s = s->next) {
            /* XXX what does this adjustment do? */
            fcgi_dynamic_last_analyzed += (((long)(now-fcgi_dynamic_last_analyzed)/dynamicUpdateInterval)*dynamicUpdateInterval);
            s->smoothConnTime = (1.0-dynamicGain)*s->smoothConnTime + dynamicGain*s->totalConnTime;
            s->totalConnTime = start_time;
            s->totalQueueTime = qsec;
        }
    }
    if (recs==0) {
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
                       execName, user, group, &qsec, &start_time, &now);
                break;
            default:
                goto CleanupReturn;
                break;
        }

        s = fcgi_util_fs_get(execName, user, group);

        if (s==NULL && opcode != REQ_COMPLETE) {
            const char *err, *lockPath;

            /* Create a perm subpool to hold the new server data,
             * we can destroy it if something doesn't pan out */
            sp = ap_make_sub_pool(fcgi_config_pool);

            /* Create a new "dynamic" server */
            s = fcgi_util_fs_new(sp);
            s->directive = APP_CLASS_DYNAMIC;
            s->restartDelay = dynamicRestartDelay;
            s->initStartDelay = dynamicInitStartDelay;
            s->envp = dynamicEnvp;
            s->fs_path = ap_pstrdup(sp, execName);
            s->procs = fcgi_util_fs_create_procs(sp, dynamicMaxClassProcs);

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

            /* Create the socket */
            if ((s->listenFd = ap_psocket(sp, s->socket_addr->sa_family, SOCK_STREAM, 0)) < 0) {
                ap_log_error(FCGI_LOG_CRIT, fcgi_apache_main_server,
                    "FastCGI: can't create (dynamic) server \"%s\": socket() failed", execName);
                goto BagNewServer;
            }

            /* bind() and listen() */
            err = bind_n_listen(tp, s->socket_addr, s->socket_addr_len,
                                     s->listenQueueDepth, s->listenFd);
            if (err) {
                ap_log_error(FCGI_LOG_CRIT, fcgi_apache_main_server,
                    "FastCGI: can't create (dynamic) server \"%s\": %s", execName, err);
                goto BagNewServer;
            }

            /* Create the lock file */
            lockPath = fcgi_util_socket_get_lock_filename(tp, s->socket_path);
            fd = ap_popenf(tp, lockPath,
                       O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
            if (fd < 0) {
                ap_log_error(FCGI_LOG_CRIT, fcgi_apache_main_server,
                    "FastCGI: can't create (dynamic) server \"%s\": can't open lock file \"%s\": popenf() failed", 
                    execName, lockPath);
                goto BagNewServer;
            }
            ap_pclosef(tp, fd);

            /* If suexec is being used, config user/group info */
            if (fcgi_suexec) {
                if (user[0] == '~') {
                    /* its a user dir uri, the rest is a username, not a uid */
                    struct passwd *pw = getpwnam(&user[1]);

                    if (!pw) {
                        ap_log_error(FCGI_LOG_CRIT, fcgi_apache_main_server,
                            "FastCGI: can't create (dynamic) server \"%s\": can't get uid/gid for suexec: getpwnam(%s) failed",
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
                            "FastCGI: can't create (dynamic) server \"%s\": can't get uid/gid for suexec: getwpuid(%ld) failed",
                            execName, (long)s->uid);
                        goto BagNewServer;
                    }
                    s->user = ap_pstrdup(sp, user);
                    s->username = ap_pstrdup(sp, pw->pw_name);

                    s->gid = (gid_t)atol(group);
                    s->group = ap_pstrdup(sp, group);
                }
            }
        fcgi_util_fs_add(s);
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
                        ap_log_error(FCGI_LOG_INFO_NOERRNO, fcgi_apache_main_server,
                            "FastCGI: restarting server \"%s\" processes, newer version found", execName);
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
                    int i, count = 0;
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
	    int i;

            case PLEASE_START:
            case CONN_TIMEOUT:
                if ((s->numProcesses + 1) > dynamicMaxClassProcs) {
                    /* Can't do anything here, log error */
                    ap_log_error(FCGI_LOG_WARNING_NOERRNO, fcgi_apache_main_server, 
                        "FastCGI: can't schedule the start of another (dynamic) server \"%s\" process: "
                        "exceeded dynamicMaxClassProcs (%d)", s->fs_path, dynamicMaxClassProcs);
                    continue;
                }
                if ((fcgi_dynamic_total_proc_count + 1) > dynamicMaxProcs) {
                    /*
                     * Extra instances should have been
                     * terminated beforehand, probably need
                     * to increase ProcessSlack parameter
                     */
                    ap_log_error(FCGI_LOG_WARNING_NOERRNO, fcgi_apache_main_server, 
                        "FastCGI: can't schedule the start of another (dynamic) server \"%s\" process: "
                        "exceeded dynamicMaxProcs (%d)", s->fs_path, dynamicMaxProcs);
                    continue;
                }
                /* find next free slot */
                for (i = 0; i < dynamicMaxClassProcs; i++) {
                    if ((s->procs[i].pid <= 0) &&
                            ((s->procs[i].state == STATE_READY) ||
                            (s->procs[i].state == STATE_NEEDS_STARTING) ||
                            (s->procs[i].state == STATE_KILLED)))
                        break;
                }
                ap_assert(i<dynamicMaxClassProcs);
                s->procs[i].state = STATE_NEEDS_STARTING;
                break;
            case REQ_COMPLETE:
                /* only record stats if we have a structure */
                if (s) {
                    s->totalConnTime += start_time;
                    s->totalQueueTime += qsec;
                }
                break;
        }

        continue;

BagNewServer:
        ap_destroy_pool(sp);
    }

CleanupReturn:
    ap_destroy_pool(tp);
    return (recs);
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
static void dynamic_kill_idle_fs_procs()
{
    fcgi_server *s;
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
    pool *tp = ap_make_sub_pool(fcgi_config_pool);

    /* pass 1 - locate and mark all victims */
    for(s=fcgi_servers;  s!=NULL; s=s->next) {
        /* Only kill dynamic apps */
        if (s->directive != APP_CLASS_DYNAMIC)
            continue;

        /* If the number of non-victims is less than or equal to
           the minimum that may be running without being killed off,
           don't select any more victims.  */
        if((fcgi_dynamic_total_proc_count-victims)<=dynamicMinProcs) {
            break;
        }
        connTime = s->smoothConnTime ? s->smoothConnTime : s->totalConnTime;
        totalTime = (s->numProcesses)*(now - fcgi_dynamic_epoch)*1000000 + 1;
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
    for(s=fcgi_servers; s!=NULL; s=s->next) {
        /* Only kill dynamic apps */
        if (s->directive != APP_CLASS_DYNAMIC)
            continue;

        for(i = 0; i < dynamicMaxClassProcs; i++) {
            if(s->procs[i].state == STATE_VICTIM) {
                lockFileName = fcgi_util_socket_get_lock_filename(tp, s->fs_path);
                if ((lockFd = ap_popenf(tp, lockFileName, O_RDWR, 0))<0) {
                    /*
                     * If we need to kill an application and the
                     * corresponding lock file does not exist, then
                     * that means we are in big trouble here
                     */
                    /*@@@ this should be logged, but since all the lock
                     * file stuff will be tossed, I'll leave it now */
                    ap_pclosef(tp, lockFd);
                    continue;
                }
                if (fcgi_get_exclusive_write_lock_no_wait(lockFd) < 0) {
                    /*
                     * Unable to lock the lockfile, indicative
                     * of WS performing operation with the given
                     * application class.  The simplest solution
                     * is to spawn off another process and block
                     * on lock to kill it.  This is under assumptions
                     * that fork() is not very costly and this
                     * situation occurs very rarely, which it should
                     */
                    funcData = ap_pcalloc(tp, sizeof(struct FuncData));
                    funcData->lockFileName = lockFileName;
                    funcData->pid = s->procs[i].pid;
                    /*
                     * We can not call onto ap_spawn_child() here
                     * since we are completely disassociated from
                     * the web server, and must do process management
                     * directly.
                     */
                    if((pid=fork())<0) {
                        /*@@@ this should be logged, but since all the lock
                         * file stuff will be tossed, I'll leave it now */
                        ap_destroy_pool(tp);
                        return;
                    } else if(pid==0) {
                        /* child */

                        /* rename the process for ps - best we can easily */
                        change_process_name("fcgiBlkKill");

                        dynamic_blocking_kill(funcData);
                    } else {
                        /* parent */
                        ap_pclosef(tp, lockFd);
                    }
                } else {
                    kill(s->procs[i].pid, SIGTERM);
                    ap_pclosef(tp, lockFd);
                    break;
                }
            }
        }
    }
    ap_destroy_pool(tp);
}


int fcgi_pm_main(void *dummy, child_info *info)
{
    fcgi_server *s;
    int i;
    int status, callWaitPid, callDynamicProcs;
    sigset_t sigMask;
    int alarmLeft = 0;
    pool *tp;
    const char *err;

    reduce_priveleges();
    
    change_process_name("fcgi-pm");

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

    if ((signal(SIGTERM, signal_handler) == SIG_ERR) ||
            (signal(SIGCHLD, signal_handler) == SIG_ERR) ||
            (signal(SIGALRM, signal_handler) == SIG_ERR) ||
            (signal(SIGUSR2, signal_handler) == SIG_ERR) ||
            (signal(SIGUSR1, signal_handler) == SIG_ERR) ||
            (signal(SIGHUP, signal_handler) == SIG_ERR)) 
    {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
            "FastCGI: process manager exiting, signal() failed");
        exit(1);
    }

    if (fcgi_suexec) {
        ap_log_error(FCGI_LOG_INFO_NOERRNO, fcgi_apache_main_server, 
            "FastCGI: suEXEC mechanism enabled (wrapper: %s)", fcgi_suexec);
    }
    
    /* Initialize AppClass */
    tp = ap_make_sub_pool(fcgi_config_pool);
    for(s = fcgi_servers; s != NULL; s = s->next) {
        if (s->directive == APP_CLASS_EXTERNAL)
        continue;

        /* Create the socket */
        s->listenFd = ap_psocket(fcgi_config_pool, s->socket_addr->sa_family, SOCK_STREAM, 0);
        if (s->listenFd < 0) {
            ap_log_error(FCGI_LOG_CRIT, fcgi_apache_main_server,
                "FastCGI: server \"%s\" disabled, socket() failed", s->fs_path);
            continue;
        }

        /* bind() and listen() */
        err = bind_n_listen(tp, s->socket_addr, s->socket_addr_len,
                                s->listenQueueDepth, s->listenFd);
        if (err) {
            ap_log_error(FCGI_LOG_CRIT, fcgi_apache_main_server,
                         "FastCGI: server \"%s\" disabled: %s",
                         s->fs_path, err);
            ap_pclosesocket(fcgi_config_pool, s->listenFd);
            s->listenFd = -1;
            continue;
        }

        for (i = 0; i < s->numProcesses; i++)
            s->procs[i].state = STATE_NEEDS_STARTING;
    }
    ap_destroy_pool(tp);
    
    ap_log_error(FCGI_LOG_INFO_NOERRNO, fcgi_apache_main_server, "FastCGI: process manager initialized");

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
        if (alarmLeft)
            sleepSeconds = alarmLeft;

        /*
         * If there is no parent process, then the Apache has
         * terminated or restarted, so perform the cleanup
         */
        if (1 == getppid())
            goto ProcessSigTerm;

        /*
         * Examine each configured AppClass for a process that needs
         * starting.  Compute the earliest time when the start should
         * be attempted, starting it now if the time has passed.  Also,
         * remember that we do NOT need to restart externally managed
         * FastCGI applications.
         */
        for (s = fcgi_servers; s != NULL; s = s->next) {
            if (s->directive == APP_CLASS_EXTERNAL || s->listenFd < 0) {
                continue;
            }
            if (s->directive == APP_CLASS_DYNAMIC) {
                numChildren = dynamicMaxClassProcs;
            } else {
                numChildren = s->numProcesses;
            }
            for (i = 0; i < numChildren; i++) {
                if ((s->procs[i].pid <= 0) &&
                    (s->procs[i].state == STATE_NEEDS_STARTING)) 
                {
                    time_t restartTime;
                    
                    now = time(NULL);

                    if (s->procs[i].pid == 0) {
                        restartTime = s->restartTime + s->initStartDelay;
                    } else {
                        restartTime = s->restartTime + s->restartDelay;
                    }

                    if(restartTime <= now) {
                        int restart = (s->procs[i].pid < 0);

                        s->restartTime = now;
                        if(caught_sigterm()) {
                            goto ProcessSigTerm;
                        }
                        status = spawn_fs_process(
                                &s->procs[i].pid,
                                s->listenFd,
                                s->processPriority,
                                s->fs_path,
                                s->envp, s->username, s->group);
                        if (status != 0) {
                            ap_log_error(FCGI_LOG_CRIT, fcgi_apache_main_server,
                                "FastCGI: can't start%s server \"%s\": spawn_fs_process() failed",
                                (s->directive == APP_CLASS_DYNAMIC) ? " (dynamic)" : "",
                                s->fs_path);
                            
                            /* do not restart failed dynamic apps */
                            if (s->directive != APP_CLASS_DYNAMIC) {
                                sleepSeconds = min(sleepSeconds,
                                        max(s->restartDelay,
                                        FCGI_MIN_EXEC_RETRY_DELAY));
                            } else {
                                s->procs[i].state = STATE_READY;
                            }
                            ap_assert(s->procs[i].pid < 0);
                            break;
                        }
                        if (s->directive == APP_CLASS_DYNAMIC) {
                            s->numProcesses++;
                            fcgi_dynamic_total_proc_count++;
                        }
                        s->procs[i].state = STATE_STARTED;

                        if (restart)
                            s->numRestarts++;

                        if (fcgi_suexec != NULL) {
                            ap_log_error(FCGI_LOG_INFO_NOERRNO, fcgi_apache_main_server,
                                "FastCGI:%s server \"%s\" (uid %ld, gid %ld) %sstarted with pid %ld",
                                (s->directive == APP_CLASS_DYNAMIC) ? " (dynamic)" : "",
                                s->fs_path, (long)s->uid, (long)s->gid, 
                                restart ? "re" : "", (long)s->procs[i].pid);
                        }
                        else {
                            ap_log_error(FCGI_LOG_INFO_NOERRNO, fcgi_apache_main_server,
                                "FastCGI:%s server \"%s\" %sstarted with pid %ld",
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
            ap_assert(sleepSeconds > 0);
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
            dynamic_read_mbox();
            now = time(NULL);
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

        /*
         * We've caught SIGCHLD, so poll for signal notifications
         * using waitpid.  If a child has died, write a log message
         * and update the data structure so we'll restart the child.
         *
         * If the last instance of the dynamic AppClass has terminated,
         * free up any memory that was associated with it.
         */
        for (;;) {
            if(caught_sigterm()) {
                goto ProcessSigTerm;
            }
            childPid = waitpid(-1, &waitStatus, WNOHANG);
            if(childPid == -1 || childPid == 0) {
                break;
            }
            for(s = fcgi_servers; s != NULL; s = s->next) {
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
                fcgi_dynamic_total_proc_count--;
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

            if (WIFEXITED(waitStatus)) {
                ap_log_error(FCGI_LOG_WARNING_NOERRNO, fcgi_apache_main_server, 
                    "FastCGI:%s server \"%s\" (pid %d) terminated by calling exit with status '%d'",
                    (s->directive == APP_CLASS_DYNAMIC) ? " (dynamic)" : "",
                    s->fs_path, (int)childPid, WEXITSTATUS(waitStatus));
            } 
            else if (WIFSIGNALED(waitStatus)) {
                ap_log_error(FCGI_LOG_WARNING_NOERRNO, fcgi_apache_main_server, 
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
                ap_log_error(FCGI_LOG_WARNING_NOERRNO, fcgi_apache_main_server, 
                    "FastCGI:%s server \"%s\" (pid %d) stopped due to uncaught signal '%d' (%s)",
                    (s->directive == APP_CLASS_DYNAMIC) ? " (dynamic)" : "",
                    s->fs_path, (int)childPid, WTERMSIG(waitStatus), SYS_SIGLIST[WTERMSIG(waitStatus)]);
            } 
        } /* for (;;) */
    } /* for (;;) */

ProcessSigTerm:
    /*
     * Kill off the children, then exit.
     */
    while (fcgi_servers != NULL) {
        kill_fs_procs(fcgi_config_pool, fcgi_servers);
    }
    exit(0);
}


