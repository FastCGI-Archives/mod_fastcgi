/*
 * $Id: fcgi_config.c,v 1.4 1999/02/24 04:38:04 roberts Exp $
 */

#include "fcgi.h"


/*******************************************************************************
 * Get the next configuration directive argument, & return an in_addr and port.
 * The arg must be in the form "host:port" where host can be an IP or hostname.
 * The pool arg should be persistant storage.
 */
static const char *get_host_n_port(pool *p, const char **arg,
        const char **host, u_int *port)
{
    char *cvptr, *portStr;

    *host = ap_getword_conf(p, arg);
    if (**host == '\0')
        return "\"\"";
        
    portStr = strchr(*host, ':');
    if (portStr == NULL)
        return "missing port specification";

    /* Split the host and port portions */
    *portStr++ = '\0';

    /* Convert port number */
    *port = (u_int)strtol(portStr, &cvptr, 10);
    if (*cvptr != '\0' || *port < 1 || *port > 65535)
        return ap_pstrcat(p, "bad port number \"", portStr, "\"", NULL);

    return NULL;
}

/*******************************************************************************
 * Get the next configuration directive argument, & return an u_int.
 * The pool arg should be temporary storage.
 */
static const char *get_u_int(pool *p, const char **arg,
        u_int *num, u_int min)
{
    char *ptr;
    const char *val = ap_getword_conf(p, arg);

    if (*val == '\0')
        return "\"\"";
    *num = (u_int)strtol(val, &ptr, 10);

    if (*ptr != '\0')
        return ap_pstrcat(p, "\"", val, "\" must be a positive integer", NULL);
    else if (*num < min)
        return ap_psprintf(p, "\"%u\" must be >= %u", *num, min);
    return NULL;
}

/*******************************************************************************
 * Get the next configuration directive argument, & return a float.
 * The pool arg should be temporary storage.
 */
static const char *get_float(pool *p, const char **arg,
        float *num, float min, float max)
{
    char *ptr;
    const char *val = ap_getword_conf(p, arg);

    if (*val == '\0')
        return "\"\"";
    *num = strtod(val, &ptr);

    if (*ptr != '\0')
        return ap_pstrcat(p, "\"", val, "\" is not a floating point number", NULL);
    if (*num < min || *num > max)
        return ap_psprintf(p, "\"%f\" is not between %f and %f", *num, min, max);
    return NULL;
}

/*******************************************************************************
 * Get the next configuration directive argument, & add it to an env array.
 * The pool arg should be permanent storage.
 */
static const char *get_env_var(pool *p, const char **arg, const char **envp, int *envc)
{
    const char * const val = ap_getword_conf(p, arg);

    if (*val == '\0')
        return "\"\"";

    if (strchr(val, '=') == NULL)
        return ap_pstrcat(p, "\"", val, "\" must contain an '='", NULL);

    if (*envc >= MAX_INIT_ENV_VARS)
        return "too many variables, must be <= MAX_INIT_ENV_VARS";

    *(envp + *envc) = val;
    (*envc)++;
    return NULL;
}

/*******************************************************************************
 * Return a "standard" message for common configuration errors.
 */
static const char *invalid_value(pool *p, const char *cmd, const char *id,
        const char *opt, const char *err)
{
    return ap_psprintf(p, "%s%s%s: invalid value for %s: %s",
                    cmd, id ? " " : "", id ? id : "",  opt, err);
}

/*******************************************************************************
 * Set/Reset the uid/gid that Apache and the PM will run as.  This is ap_user_id
 * and ap_group_id if we're started as root, and euid/egid otherwise.  Also try
 * to check that the config files don't set the User/Group after a FastCGI
 * directive is used that depends on it.
 */
/*@@@ To be complete, we should save a handle to the server each AppClass is
 * configured in and at init() check that the user/group is still what we
 * thought it was.  Also the other directives should only be allowed in the
 * parent Apache server.
 */
const char *fcgi_config_set_fcgi_uid_n_gid(int set)
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

    uid = uid ? uid : ap_user_id;
    gid = uid ? gid : ap_group_id;

    if (isSet && (uid != fcgi_user_id || gid != fcgi_group_id)) {
        return "User/Group commands must preceed FastCGI server definitions";
    }

    isSet = 1;
    fcgi_user_id = uid;
    fcgi_group_id = gid;
    return NULL;
}

void fcgi_config_reset_globals(void* dummy)
{
    fcgi_config_pool = NULL;
    fcgi_servers = NULL;
    fcgi_config_set_fcgi_uid_n_gid(0);
    fcgi_suexec = NULL;
    fcgi_socket_dir = DEFAULT_SOCK_DIR;
    /* fcgi_dynamic_total_proc_count = 0; */

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
const char *fcgi_config_make_dir(pool *tp, char *path)
{
    struct stat finfo;
    const char *err = NULL;

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
            return ap_psprintf(tp,
                "doesn't exist and can't be created: %s",
                strerror(errno));
        }

        /* If we're root, we're gonna setuid/setgid so we need to chown */
        if (geteuid() == 0 && chown(path, ap_user_id, ap_group_id) != 0) {
            return ap_psprintf(tp,
                "can't chown() to the server (uid %ld, gid %ld): %s",
                (long)ap_user_id, (long)ap_group_id, strerror(errno));
        }
    }
    else {
        /* Yes, is it a directory? */
        if (!S_ISDIR(finfo.st_mode))
            return "isn't a directory!";

        /* Can we RWX in there? */
        err = fcgi_util_check_access(tp, NULL, &finfo, R_OK | W_OK | X_OK,
                          fcgi_user_id, fcgi_group_id);
        if (err != NULL) {
            return ap_psprintf(tp,
                "access for server (uid %ld, gid %ld) failed: %s",
                (long)fcgi_user_id, (long)fcgi_group_id, err);
        }
    }
    return NULL;
}

/*******************************************************************************
 * Create a "dynamic" subdirectory and fcgi_dynamic_mbox (used for RH->PM comm) in the
 * fcgi_socket_dir with appropriate permissions.
 */
const char *fcgi_config_make_dynamic_dir_n_mbox(pool *p)
{
    DIR *dp = NULL;
    struct dirent *dirp = NULL;
    int fd;
    const char *err;
    pool *tp;

    fcgi_dynamic_dir = ap_pstrcat(p, fcgi_socket_dir, "/dynamic", NULL);

    err = fcgi_config_make_dir(p, fcgi_dynamic_dir);
    if (err != NULL) {
        return ap_psprintf(p,
            "can't create dynamic directory \"%s\": %s",
            fcgi_dynamic_dir, err);
    }

    /* Create a subpool for the directory operations */
    tp = ap_make_sub_pool(p);

    dp = ap_popendir(tp, fcgi_dynamic_dir);
    if (dp == NULL) {
        ap_destroy_pool(tp);
        return ap_psprintf(p, "can't open dynamic directory \"%s\": %s",
            fcgi_dynamic_dir, strerror(errno));
    }

    /* Delete everything in the directory, its all FCGI specific */
    while ((dirp = readdir(dp)) != NULL) {
        if (strcmp(dirp->d_name, ".") == 0
                || strcmp(dirp->d_name, "..") == 0) {
            continue;
        }

        unlink(ap_pstrcat(tp, fcgi_dynamic_dir, "/", dirp->d_name, NULL));
    }

    ap_destroy_pool(tp);

    /* Create fcgi_dynamic_mbox */
    fcgi_dynamic_mbox = ap_pstrcat(p, fcgi_dynamic_dir, "/fcgi_dynamic_mbox", NULL);

    /* @@@ This really should be a socket or pipe */
    fd = ap_popenf(p, fcgi_dynamic_mbox, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return ap_psprintf(p, "can't create \"%s\": %s",
            fcgi_dynamic_mbox, strerror(errno));
    }

    /* If we're root, were gonna setuid/setgid so chown */
    if (geteuid() == 0 && fchown(fd, ap_user_id, ap_group_id) != 0) {
        return ap_psprintf(p,
            "can't chown() \"%s\" to server (uid %ld, gid %ld): %s",
            fcgi_dynamic_mbox, (long)ap_user_id, (long)ap_group_id, strerror(errno));
    }
    ap_pclosef(p, fd);

    return NULL;
}


/*******************************************************************************
 * Change the directory used for the Unix/Domain sockets from the default.
 * Create the directory, the "dynamic" subdirectory, and the fcgi_dynamic_mbox used for
 * comm between the RH and the PM (we do this here, as well as in
 * fastcgi_init, so we can prevent Apache from starting if it fails).
 */
const char *fcgi_config_set_socket_dir(cmd_parms *cmd, void *dummy, char *arg)
{
    pool * const tp = cmd->temp_pool;
    const char * const name = cmd->cmd->name;
    const char *err;

    if (strcmp(fcgi_socket_dir, DEFAULT_SOCK_DIR) != 0) {
        return ap_psprintf(tp, "%s %s: already defined as \"%s\"",
                        name, arg, fcgi_socket_dir);
    }

    err = fcgi_config_set_fcgi_uid_n_gid(1);
    if (err != NULL)
        return ap_psprintf(tp, "%s %s: %s", name, arg, err);

    if (fcgi_servers != NULL) {
        return ap_psprintf(tp,
            "The %s command must preceed static FastCGI server definitions",
            name);
    }

    if (!ap_os_is_path_absolute(arg))
        arg = ap_make_full_path(cmd->pool, ap_server_root, arg);
    
    fcgi_socket_dir = arg;

    err = fcgi_config_make_dir(tp, fcgi_socket_dir);
    if (err != NULL)
        return ap_psprintf(tp, "%s %s: %s", name, arg, err);

    err = fcgi_config_make_dynamic_dir_n_mbox(cmd->pool);
    if (err != NULL)
        return ap_psprintf(tp, "%s %s: %s", name, arg, err);

    return NULL;
}

/*******************************************************************************
 * Enable, disable, or specify the path to the suexec program.
 */
const char *fcgi_config_set_suexec(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = NULL;
    const char * const name = cmd->cmd->name;
    pool * const tp = cmd->temp_pool;

    if (!ap_suexec_enabled) {
        if (strcasecmp(arg, "Off") != 0) {
	        fprintf(stderr, "Warning: %s requires SUEXEC wrapper be enabled in Apache\n", name);
	    }
	    return NULL;
    }

    err = fcgi_config_set_fcgi_uid_n_gid(1);
    if (err != NULL)
        return ap_psprintf(tp, "%s %s: %s", name, arg, err);

    if (fcgi_servers != NULL) {
        return ap_psprintf(tp,
            "The %s command must preceed static FastCGI server definitions", name);
    }

    if (strcasecmp(arg, "On") == 0) {
        fcgi_suexec = SUEXEC_BIN;
    }
    else if (strcasecmp(arg, "Off") == 0) {
        fcgi_suexec = NULL;
    }
    else {
        if (!ap_os_is_path_absolute(arg))
            arg = ap_make_full_path(cmd->pool, ap_server_root, arg);
    
        err = fcgi_util_check_access(tp, arg, NULL, X_OK, fcgi_user_id, fcgi_group_id);
        if (err != NULL) {
            return ap_psprintf(tp,
                "%s: \"%s\" access for server (uid %ld, gid %ld) failed: %s",
                name, arg, (long)fcgi_user_id, (long)fcgi_group_id, err);
        }

        fcgi_suexec = arg;
    }
    return NULL;
}

/*******************************************************************************
 * Configure a static FastCGI server.
 */
const char *fcgi_config_new_static_server(cmd_parms *cmd, void *dummy, const char *arg)
{
    fcgi_server *s;
    pool *p = cmd->pool, *tp = cmd->temp_pool;
    const char *name = cmd->cmd->name;
    const char *fs_path = ap_getword_conf(p, &arg);
    const char *option, *err;

    /* Allocate temp storage for the array of initial environment variables */
    const char **envp = ap_pcalloc(tp, sizeof(char *) * (MAX_INIT_ENV_VARS + 1));
    int envc = 0;

    if (*fs_path == '\0')
        return "AppClass requires a pathname!?";

    if ((err = fcgi_config_set_fcgi_uid_n_gid(1)) != NULL)
        return ap_psprintf(tp, "%s %s: %s", name, fs_path, err);
    
    if (!ap_os_is_path_absolute(fs_path))
        fs_path = ap_make_full_path(p, ap_server_root, fs_path);
        
    /* See if we've already got one of these configured */
    s = fcgi_util_fs_get_by_id(fs_path, cmd->server->server_uid,
                       cmd->server->server_gid);
    if (s != NULL) {
        if (fcgi_suexec) {
            return ap_psprintf(tp,
                "%s: redefinition of a previously defined FastCGI server \"%s\" with uid=%ld and gid=%ld",
                name, fs_path, (long)cmd->server->server_uid,
                (long)cmd->server->server_gid);
        }
        else {
            return ap_psprintf(tp,
                "%s: redefinition of a previously defined FastCGI server \"%s\"",
                name, fs_path);
        }
    }

    err = fcgi_util_fs_is_path_ok(tp, fs_path, NULL, cmd->server->server_uid,
                          cmd->server->server_gid);
    if (err != NULL) {
        return ap_psprintf(tp, "%s: \"%s\" %s", name, fs_path, err);
    }
          
    s = fcgi_util_fs_new(p);
    s->fs_path = fs_path;
    s->directive = APP_CLASS_STANDARD;
    s->restartOnExit = TRUE;
    s->numProcesses = 1;

    if (fcgi_suexec) {
        struct passwd *pw;
        struct group  *gr;

        s->uid = cmd->server->server_uid;
        pw = getpwuid(s->uid);
        if (pw == NULL) {
            return ap_psprintf(tp, "mod_fastcgi: "
                "getpwuid() couldn't determine the username for uid '%ld', "
                "you probably need to modify the User directive: %s",
                (long)s->uid, strerror(errno));
        }
        s->user = ap_pstrdup(p, pw->pw_name);
        s->username = s->user;

        s->gid = cmd->server->server_gid;
        gr = getgrgid(s->gid);
        if (gr == NULL) {
            return ap_psprintf(tp, "mod_fastcgi: "
                "getgrgid() couldn't determine the group name for gid '%ld', "
                "you probably need to modify the Group directive: %s\n",
                (long)s->gid, strerror(errno));
        }
        s->group = ap_pstrdup(p, gr->gr_name);
    }

    /*  Parse directive arguments */
    while (*arg) {
        option = ap_getword_conf(tp, &arg);

        if (strcasecmp(option, "-processes") == 0) {
            err = get_u_int(tp, &arg, &s->numProcesses, 1);
            if (err != NULL)
                return invalid_value(tp, name, fs_path, option, err);
            continue;
        }
        else if (strcasecmp(option, "-restart-delay") == 0) {
            err = get_u_int(tp, &arg, &s->restartDelay, 0);
            if (err != NULL)
                return invalid_value(tp, name, fs_path, option, err);
            continue;
        }
        else if (strcasecmp(option, "-init-start-delay") == 0) {
            err = get_u_int(tp, &arg, &s->initStartDelay, 0);
            if (err != NULL)
                return invalid_value(tp, name, fs_path, option, err);
            continue;
        }
        else if (strcasecmp(option, "-priority") == 0) {
            err = get_u_int(tp, &arg, &s->processPriority, 0);
            if (err != NULL)
                return invalid_value(tp, name, fs_path, option, err);
            continue;
        }
        else if (strcasecmp(option, "-listen-queue-depth") == 0) {
            err = get_u_int(tp, &arg, &s->listenQueueDepth, 1);
            if (err != NULL)
                return invalid_value(tp, name, fs_path, option, err);
            continue;
        }
        else if (strcasecmp(option, "-appConnTimeout") == 0) {
            err = get_u_int(tp, &arg, &s->appConnectTimeout, 0);
            if (err != NULL)
                return invalid_value(tp, name, fs_path, option, err);
            continue;
        }
        else if (strcasecmp(option, "-port") == 0) {
            err = get_u_int(tp, &arg, &s->port, 1);
            if (err != NULL)
                return invalid_value(tp, name, fs_path, option, err);
            continue;
        }
        else if (strcasecmp(option, "-socket") == 0) {
            s->socket_path = ap_getword_conf(tp, &arg);
            if (*s->socket_path == '\0')
                return invalid_value(tp, name, fs_path, option, "\"\"");
            continue;
        }
        else if (strcasecmp(option, "-initial-env") == 0) {
            err = get_env_var(p, &arg, envp, &envc);
            if (err != NULL)
                return invalid_value(tp, name, fs_path, option, err);
            continue;
        }
        else if (strcasecmp(option, "-flush") == 0) {
            s->flush = 1;
            continue;
        }
        else
            return invalid_value(tp, name, fs_path, option, NULL);
    } /* while */

    if (s->socket_path != NULL && s->port != 0) {
        return ap_psprintf(tp,
                "%s %s: -port and -socket are mutually exclusive options",
                name, fs_path);
    }

    /* If -intial-env option was used, move env array to a surviving pool */
    if (envc++) {
        s->envp = (const char **)ap_palloc(p, sizeof(char *) * envc);
        memcpy(s->envp, envp, sizeof(char *) * envc);
    }

    /* Initialize process structs */
    s->procs = fcgi_util_fs_create_procs(p, s->numProcesses);

    /* Build the appropriate sockaddr structure */
    if (s->port != 0) {
        err = fcgi_util_socket_make_inet_addr(p, (struct sockaddr_in **)&s->socket_addr,
                                &s->socket_addr_len, NULL, s->port);
        if (err != NULL)
            return ap_psprintf(tp, "%s %s: %s", name, fs_path, err);
    } else {
        if (s->socket_path == NULL)
             s->socket_path = fcgi_util_socket_hash_filename(tp, fs_path, s->user, s->group);
        s->socket_path = fcgi_util_socket_make_path_absolute(p, s->socket_path, 0);
        err = fcgi_util_socket_make_domain_addr(p, (struct sockaddr_un **)&s->socket_addr,
                                  &s->socket_addr_len, s->socket_path);
        if (err != NULL)
            return ap_psprintf(tp, "%s %s: %s", name, fs_path, err);
    }

    /* Add it to the list of FastCGI servers */
    fcgi_util_fs_add(s);

    return NULL;
}

/*******************************************************************************
 * Configure a static FastCGI server that is started/managed elsewhere.
 */
const char *fcgi_config_new_external_server(cmd_parms *cmd, void *dummy, const char *arg)
{
    fcgi_server *s;
    pool * const p = cmd->pool, *tp = cmd->temp_pool;
    const char * const name = cmd->cmd->name;
    const char *fs_path = ap_getword_conf(p, &arg);
    const char *option, *err;

    if (!*fs_path) {
        return ap_pstrcat(tp, name,
            " requires a path and either a -socket or -host option", NULL);
    }
    
    if (!ap_os_is_path_absolute(fs_path))
        fs_path = ap_make_full_path(p, ap_server_root, fs_path);
    
    /* See if we've already got one of these bettys configured */
    s = fcgi_util_fs_get_by_id(fs_path, cmd->server->server_uid,
                       cmd->server->server_gid);
    if (s != NULL) {
        if (fcgi_suexec != NULL) {
            return ap_psprintf(tp,
                "%s: redefinition of a previously defined class \"%s\" with uid=%ld and gid=%ld",
                name, fs_path, (long)cmd->server->server_uid,
                (long)cmd->server->server_gid);
        }
        else {
            return ap_psprintf(tp,
                "%s: redefinition of previously defined class \"%s\"",
                name, fs_path);
        }
    }

    s = fcgi_util_fs_new(p);
    s->fs_path = fs_path;
    s->directive = APP_CLASS_EXTERNAL;

    err = fcgi_util_fs_set_uid_n_gid(p, s, cmd->server->server_uid, cmd->server->server_gid);
    if (err != NULL)
        return ap_psprintf(tp, "%s %s: %s", name, fs_path, err);

    /*  Parse directive arguments */
    while (*arg != '\0') {
        option = ap_getword_conf(tp, &arg);

        if (strcasecmp(option, "-host") == 0) {
            err = get_host_n_port(p, &arg, &s->host, &s->port);
            if (err != NULL)
                return invalid_value(tp, name, fs_path, option, err);
            continue;
        }
        else if (strcasecmp(option, "-socket") == 0) {
            s->socket_path = ap_getword_conf(tp, &arg);
            if (*s->socket_path == '\0')
                return invalid_value(tp, name, fs_path, option, "\"\"");
            continue;
        }
        else if (strcasecmp(option, "-appConnTimeout") == 0) {
            err = get_u_int(tp, &arg, &s->appConnectTimeout, 0);
            if (err != NULL)
                return invalid_value(tp, name, fs_path, option, err);
            continue;
        }
        else if (strcasecmp(option, "-flush") == 0) {
            s->flush = 1;
            continue;
        }
        else {
            return ap_psprintf(tp, "%s %s: invalid option: %s",
                            name, fs_path, option);
        }
    } /* while */

    /* Require one of -socket or -host, but not both */
    if (s->socket_path != NULL && s->port != 0) {
        return ap_psprintf(tp,
            "%s %s: -host and -socket are mutually exclusive options",
            name, fs_path);
    }
    if (s->socket_path == NULL && s->port == 0) {
        return ap_psprintf(tp,
            "%s %s: -socket or -host option missing", name, fs_path);
    }

    /* Build the appropriate sockaddr structure */
    if (s->port != 0) {
        err = fcgi_util_socket_make_inet_addr(p, (struct sockaddr_in **)&s->socket_addr,
                                &s->socket_addr_len, NULL, s->port);
        if (err != NULL)
            return ap_psprintf(tp, "%s %s: %s", name, fs_path, err);
    } else {
        s->socket_path = fcgi_util_socket_make_path_absolute(p, s->socket_path, 0);
        err = fcgi_util_socket_make_domain_addr(p, (struct sockaddr_un **)&s->socket_addr,
                                  &s->socket_addr_len, s->socket_path);
        if (err != NULL)
            return ap_psprintf(tp, "%s %s: %s", name, fs_path, err);
    }

    /* Add it to the list of FastCGI servers */
    fcgi_util_fs_add(s);

    return NULL;
}

/*
 *----------------------------------------------------------------------
 *
 * fcgi_config_set_config --
 *
 *      Implements the FastCGI FCGIConfig configuration directive.
 *      This command adds routines to control the execution of the
 *      dynamic FastCGI processes.
 *
 *
 *----------------------------------------------------------------------
 */
const char *fcgi_config_set_config(cmd_parms *cmd, void *dummy, const char *arg)
{
    pool * const p = cmd->pool;
    pool * const tp = cmd->temp_pool;
    const char *err, *option;
    const char * const name = cmd->cmd->name;

    /* Allocate temp storage for an initial environment */
    int envc = 0;
    const char **envp = (const char **)ap_pcalloc(tp, sizeof(char *) * (MAX_INIT_ENV_VARS + 1));

    /* Parse the directive arguments */
    while (*arg) {
        option = ap_getword_conf(tp, &arg);

        if (strcasecmp(option, "-maxProcesses") == 0) {
            err = get_u_int(tp, &arg, &dynamicMaxProcs, 1);
            if (err != NULL)
                return invalid_value(tp, name, NULL, option, err);
            continue;
        }
        else if (strcasecmp(option, "-minProcesses") == 0) {
            err = get_u_int(tp, &arg, &dynamicMinProcs, 0);
            if (err != NULL)
                return invalid_value(tp, name, NULL, option, err);
            continue;
        }
        else if (strcasecmp(option, "-maxClassProcesses") == 0) {
            err = get_u_int(tp, &arg, &dynamicMaxClassProcs, 1);
            if (err != NULL)
                return invalid_value(tp, name, NULL, option, err);
            continue;
        }
        else if (strcasecmp(option, "-killInterval") == 0) {
            err = get_u_int(tp, &arg, &dynamicKillInterval, 1);
            if (err != NULL)
                return invalid_value(tp, name, NULL, option, err);
            continue;
        }
        else if (strcasecmp(option, "-updateInterval") == 0) {
            err = get_u_int(tp, &arg, &dynamicUpdateInterval, 1);
            if (err != NULL)
                return invalid_value(tp, name, NULL, option, err);
            continue;
        }
        else if (strcasecmp(option, "-gainValue") == 0) {
            err = get_float(tp, &arg, &dynamicGain, 0.0, 1.0);
            if (err != NULL)
                return invalid_value(tp, name, NULL, option, err);
            continue;
        }
        else if (strcasecmp(option, "-singleThreshhold") == 0) {
            err = get_u_int(tp, &arg, &dynamicThreshhold1, 1);
            if (err != NULL)
                return invalid_value(tp, name, NULL, option, err);
            continue;
        }
        else if (strcasecmp(option, "-multiThreshhold") == 0) {
            err = get_u_int(tp, &arg, &dynamicThreshholdN, 1);
            if (err != NULL)
                return invalid_value(tp, name, NULL, option, err);
            continue;
        }
        else if (strcasecmp(option, "-startDelay") == 0) {
            err = get_u_int(tp, &arg, &dynamicPleaseStartDelay, 1);
            if (err != NULL)
                return invalid_value(tp, name, NULL, option, err);
            continue;
        }
        else if (strcasecmp(option, "-initial-env") == 0) {
            err = get_env_var(p, &arg, envp, &envc);
            if (err != NULL)
                return invalid_value(tp, name, NULL, option, err);
            continue;
        }
        else if (strcasecmp(option, "-appConnTimeout") == 0) {
            err = get_u_int(tp, &arg, &dynamicAppConnectTimeout, 0);
            if (err != NULL)
                return invalid_value(tp, name, NULL, option, err);
            continue;
        }
        else if (strcasecmp(option, "-listen-queue-depth") == 0) {
            err = get_u_int(tp, &arg, &dynamicListenQueueDepth, 1);
            if (err != NULL)
                return invalid_value(tp, name, NULL, option, err);
            continue;
        }
        else if (strcasecmp(option, "-restart-delay") == 0) {
            err = get_u_int(tp, &arg, &dynamicRestartDelay, 0);
            if (err != NULL)
                return invalid_value(tp, name, NULL, option, err);
            continue;
        }
        else if (strcasecmp(option, "-init-start-delay") == 0) {
            err = get_u_int(tp, &arg, &dynamicInitStartDelay, 0);
            if (err != NULL)
                return invalid_value(tp, name, NULL, option, err);
            continue;
        }
        else if (strcasecmp(option, "-processSlack") == 0) {
            err = get_u_int(tp, &arg, &dynamicProcessSlack, 1);
            if (err != NULL)
                return invalid_value(tp, name, NULL, option, err);
            continue;
        }
        else if (strcasecmp(option, "-restart") == 0) {
            dynamicAutoRestart = 1;
            continue;
        }
        else if (strcasecmp(option, "-autoUpdate") == 0) {
            dynamicAutoUpdate = 1;
            continue;
        }
        else {
            return ap_psprintf(tp, "%s: invalid option: %s", name, option);
        }
    } /* while */

    /* If -intial-env option was used, move env array to a surviving pool */
    if (envc++) {
        dynamicEnvp = (const char **)ap_palloc(p, sizeof(char *) * envc);
        memcpy(dynamicEnvp, envp, sizeof(char *) * envc); 
    }

    return NULL;
}

void *fcgi_config_create_dir_config(pool *p, char *dummy)
{
    fcgi_dir_config *dir_config = ap_pcalloc(p, sizeof(fcgi_dir_config));
    
    dir_config->authenticator_options = FCGI_AUTHORITATIVE;
    dir_config->authorizer_options = FCGI_AUTHORITATIVE;
    dir_config->access_checker_options = FCGI_AUTHORITATIVE;
    
    return dir_config;
}


const char *fcgi_config_new_auth_server(cmd_parms * const cmd, 
    fcgi_dir_config *dir_config, const char *fs_path, const char * const compat)
{
    pool * const tp = cmd->temp_pool;
    const uid_t uid = cmd->server->server_uid;
    const gid_t gid = cmd->server->server_gid;
   
    if (!ap_os_is_path_absolute(fs_path))
        fs_path = ap_make_full_path(cmd->pool, ap_server_root, fs_path);

    /* Make sure its already configured or at least a candidate for dynamic */
    if (fcgi_util_fs_get_by_id(fs_path, uid, gid) == NULL) {
        const char *err = fcgi_util_fs_is_path_ok(tp, fs_path, NULL, uid, gid);
        if (err)
            return ap_psprintf(tp, "%s: \"%s\" %s", cmd->cmd->name, fs_path, err);
    }
    
    if (compat && strcasecmp(compat, "-compat"))
        return ap_psprintf(cmd->temp_pool, "%s: unknown option: \"%s\"", cmd->cmd->name, compat);
    
    switch((int)cmd->info) {
        case FCGI_AUTH_TYPE_AUTHENTICATOR:
            dir_config->authenticator = fs_path;
            dir_config->authenticator_options |= (compat) ? FCGI_COMPAT : 0;
            break;
        case FCGI_AUTH_TYPE_AUTHORIZER:
            dir_config->authorizer = fs_path;
            dir_config->authorizer_options |= (compat) ? FCGI_COMPAT : 0;
            break;        
        case FCGI_AUTH_TYPE_ACCESS_CHECKER:
            dir_config->access_checker = fs_path;
            dir_config->access_checker_options |= (compat) ? FCGI_COMPAT : 0;
            break;
    }                
                 
    return NULL;
}

const char *fcgi_config_set_authoritative_slot(const cmd_parms * const cmd, 
    fcgi_dir_config * const dir_config, int arg)
{
    int offset = (int)(long)cmd->info;
    
    if (arg)
        *(int *)(dir_config + offset) |= FCGI_AUTHORITATIVE;
    else
        *(int *)(dir_config + offset) &= ~FCGI_AUTHORITATIVE;
    
    return NULL;
}    
