/*
 * $Id: fcgi_util.c,v 1.12 2000/05/12 13:52:29 robs Exp $
 */

#include "fcgi.h"
 
/*******************************************************************************
 * Compute printable MD5 hash. Pool p is used for scratch as well as for
 * allocating the hash - use temp storage, and dup it if you need to keep it.
 */
char *
fcgi_util_socket_hash_filename(pool *p, const char *path,
        const char *user, const char *group)
{
    char *buf = ap_pstrcat(p, path, user, group, NULL);

    /* Canonicalize the path (remove "//", ".", "..") */
    ap_getparents(buf);

    return ap_md5(p, (unsigned char *)buf);
}

/*******************************************************************************
 * Return absolute path to file in either "regular" FCGI socket directory or
 * the dynamic directory.  Result is allocated in pool p.
 */
const char *
fcgi_util_socket_make_path_absolute(pool * const p, 
        const char *const file, const int dynamic)
{
    return (const char *)ap_pstrcat(p, 
#ifdef WIN32
        (dynamic ? fcgi_dynamic_dir : fcgi_socket_dir), file, NULL);
#else
        (dynamic ? fcgi_dynamic_dir : fcgi_socket_dir), "/", file, NULL);
#endif
}

/*******************************************************************************
 * Allocate a new string from pool p with the name of a Unix/Domain socket's
 * lock file (used by dynamic only).
 */
const char *
fcgi_util_socket_get_lock_filename(pool *p, const char *socket_path)
{
    return ap_pstrcat(p, socket_path, ".lock", NULL);
}

#ifndef WIN32
/*******************************************************************************
 * Build a Domain Socket Address structure, and calculate its size.
 * The error message is allocated from the pool p.  If you don't want the
 * struct sockaddr_un also allocated from p, pass it preallocated (!=NULL).
 */
const char *
fcgi_util_socket_make_domain_addr(pool *p, struct sockaddr_un **socket_addr,
        int *socket_addr_len, const char *socket_path)
{
    int socket_pathLen = strlen(socket_path);

    if (socket_pathLen >= sizeof((*socket_addr)->sun_path)) {
        return ap_pstrcat(p, "path \"", socket_path,
                       "\" is too long for a Domain socket", NULL);
    }

    if (*socket_addr == NULL)
        *socket_addr = ap_pcalloc(p, sizeof(struct sockaddr_un));
    else
        memset(*socket_addr, 0, sizeof(struct sockaddr_un));

    (*socket_addr)->sun_family = AF_UNIX;
    strcpy((*socket_addr)->sun_path, socket_path);

    *socket_addr_len = SUN_LEN(*socket_addr);
    return NULL;
}
#endif

/*******************************************************************************
 * Convert a hostname or IP address string to an in_addr struct.
 */
static int 
convert_string_to_in_addr(const char * const hostname, struct in_addr * const addr)
{
    struct hostent *hp;
    int count;

    addr->s_addr = inet_addr((char *)hostname);
    
    if (addr->s_addr == INADDR_NONE) {
        if ((hp = gethostbyname((char *)hostname)) == NULL)
            return -1;

        memcpy((char *) addr, hp->h_addr, hp->h_length);
        count = 0;
        while (hp->h_addr_list[count] != 0)
            count++;

        return count;
    }
    return 1;
}


/*******************************************************************************
 * Build an Inet Socket Address structure, and calculate its size.
 * The error message is allocated from the pool p. If you don't want the
 * struct sockaddr_in also allocated from p, pass it preallocated (!=NULL).
 */
const char *
fcgi_util_socket_make_inet_addr(pool *p, struct sockaddr_in **socket_addr,
        int *socket_addr_len, const char *host, unsigned short port)
{
    if (*socket_addr == NULL)
        *socket_addr = ap_pcalloc(p, sizeof(struct sockaddr_in));
    else
        memset(*socket_addr, 0, sizeof(struct sockaddr_in));

    (*socket_addr)->sin_family = AF_INET;
    (*socket_addr)->sin_port = htons(port);

    /* Get an in_addr represention of the host */
    if (host != NULL) {
        if (convert_string_to_in_addr(host, &(*socket_addr)->sin_addr) != 1) {
            return ap_pstrcat(p, "failed to resolve \"", host,
                           "\" to exactly one IP address", NULL);
        }
    } else {
      (*socket_addr)->sin_addr.s_addr = htonl(INADDR_ANY);
    }

    *socket_addr_len = sizeof(struct sockaddr_in);
    return NULL;
}

/*******************************************************************************
 * Determine if a process with uid/gid can access a file with mode permissions.
 */
const char *
fcgi_util_check_access(pool *tp, 
        const char * const path, const struct stat *statBuf, 
        const int mode, const uid_t uid, const gid_t gid)
{
    if (statBuf == NULL) {
        static struct stat staticStatBuf;
        
        if (stat(path, &staticStatBuf) < 0)
            return ap_psprintf(tp, "stat() failed: %s", strerror(errno));
        statBuf = &staticStatBuf;
    }
    
#ifndef WIN32    
    /* If the uid owns the file, check the owner bits */
    if (uid == statBuf->st_uid) {
        if (mode & R_OK && !(statBuf->st_mode & S_IRUSR))
            return "read not allowed by owner";
        if (mode & W_OK && !(statBuf->st_mode & S_IWUSR))
            return "write not allowed by owner";
        if (mode & X_OK && !(statBuf->st_mode & S_IXUSR))
            return "execute not allowed by owner";
        return NULL;
    }
#else
    if (mode & _S_IREAD && !(statBuf->st_mode & _S_IREAD))
        return "read not allowed";
    if (mode & _S_IWRITE && !(statBuf->st_mode & _S_IWRITE))
        return "write not allowed";
    
    // I don't think this works on FAT, but since I don't know how to check..
    // if (mode & _S_IEXEC && !(statBuf->st_mode & _S_IEXEC))
    //     return "execute not allowed";
#endif

#if  !defined(__EMX__) && !defined(WIN32)
    /* If the gid is same as the file's group, check the group bits */
    if (gid == statBuf->st_gid) {
        if (mode & R_OK && !(statBuf->st_mode & S_IRGRP))
            return "read not allowed by group";
        if (mode & W_OK && !(statBuf->st_mode & S_IWGRP))
            return "write not allowed by group";
        if (mode & X_OK && !(statBuf->st_mode & S_IXGRP))
            return "execute not allowed by group";
        return NULL;
    }

    /* Get the user membership for the file's group.  If the
     * uid is a member, check the group bits. */
    {
        const struct group * const gr = getgrgid(statBuf->st_gid);
        const struct passwd * const pw = getpwuid(uid);

        if (gr != NULL && pw != NULL) {
            char **user = gr->gr_mem;
            for ( ; *user != NULL; user++) {
                if (strcmp(*user, pw->pw_name) == 0) {
                    if (mode & R_OK && !(statBuf->st_mode & S_IRGRP))
                        return "read not allowed by group";
                    if (mode & W_OK && !(statBuf->st_mode & S_IWGRP))
                        return "write not allowed by group";
                    if (mode & X_OK && !(statBuf->st_mode & S_IXGRP))
                        return "execute not allowed by group";
                    return NULL;
                }
            }
        }
    }
    
    /* That just leaves the other bits.. */
    if (mode & R_OK && !(statBuf->st_mode & S_IROTH))
        return "read not allowed";
    if (mode & W_OK && !(statBuf->st_mode & S_IWOTH))
        return "write not allowed";
    if (mode & X_OK && !(statBuf->st_mode & S_IXOTH))
        return "execute not allowed";
#endif

    return NULL;
}


/*******************************************************************************
 * Find a FastCGI server with a matching fs_path, and if fcgi_suexec is
 * enabled with matching uid and gid.
 */
fcgi_server *
fcgi_util_fs_get_by_id(const char *ePath, uid_t uid, gid_t gid)
{
    char path[FCGI_MAXPATH];
    fcgi_server *s;

    /* @@@ This should now be done in the loop below */
    ap_cpystrn(path, ePath, FCGI_MAXPATH);
    ap_no2slash(path);

    for (s = fcgi_servers; s != NULL; s = s->next) {
        int i;
        const char *fs_path = s->fs_path;
        for (i = 0; fs_path[i] && path[i]; ++i) {
            if (fs_path[i] != path[i]) {
                break;
            }
        }
        if (fs_path[i]) {
            continue;
        }
        if (path[i] == '\0' || path[i] == '/') {
        if (fcgi_suexec == NULL || (uid == s->uid && gid == s->gid))
            return s;
        }
    }
    return NULL;
}

/*******************************************************************************
 * Find a FastCGI server with a matching fs_path, and if fcgi_suexec is
 * enabled with matching user and group.
 */
fcgi_server *
fcgi_util_fs_get(const char *ePath, const char *user, const char *group)
{
    char path[FCGI_MAXPATH];
    fcgi_server *s;

    ap_cpystrn(path, ePath, FCGI_MAXPATH);
    ap_no2slash(path);
    
    for (s = fcgi_servers; s != NULL; s = s->next) {
        if (strcmp(s->fs_path, path) == 0) {
            if (fcgi_suexec == NULL)
                return s;

            if (strcmp(user, s->user) == 0 
                && (user[0] == '~' || strcmp(group, s->group) == 0))
            {
                return s;
            }
        }
    }
    return NULL;
}

const char *
fcgi_util_fs_is_path_ok(pool * const p, const char * const fs_path, 
        struct stat *finfo, const uid_t uid, const gid_t gid)
{
    const char *err;
    
    if (finfo == NULL) {
        finfo = (struct stat *)ap_palloc(p, sizeof(struct stat));	        
        if (stat(fs_path, finfo) < 0)
            return ap_psprintf(p, "stat() failed: %s", strerror(errno));
    }

    /* No Parse Header scripts aren't allowed.
     * @@@ Well... we really could quite easily */ 
    if (strncmp(strrchr(fs_path, '/'), "/nph-", 5) == 0)
        return ap_psprintf(p, "NPH scripts cannot be run as FastCGI");
    
    if (finfo->st_mode == 0) 
        return ap_psprintf(p, "script not found or unable to stat()");

    if (S_ISDIR(finfo->st_mode)) 
        return ap_psprintf(p, "script is a directory!");
    
    if (fcgi_suexec != NULL) {
#ifndef WIN32
        err = fcgi_util_check_access(p, fs_path, finfo, X_OK, uid, gid);
        if (err) {
            return ap_psprintf(p,
                "access for fcgi_suexec (uid %ld, gid %ld) not allowed: %s",
                (long)uid, (long)gid, err);
        }
#endif
    }
    else {
#ifdef WIN32
        err = fcgi_util_check_access(p, fs_path, finfo, _S_IEXEC, fcgi_user_id, fcgi_group_id);
#else
        err = fcgi_util_check_access(p, fs_path, finfo, X_OK, fcgi_user_id, fcgi_group_id);
#endif
        if (err) {
            return ap_psprintf(p,
                "access for server (uid %ld, gid %ld) not allowed: %s",
                (long)fcgi_user_id, (long)fcgi_group_id, err);
        }
    }

    return NULL;
}



/*******************************************************************************
 * Allocate a new FastCGI server record from pool p with default values.
 */
fcgi_server *
fcgi_util_fs_new(pool *p)
{
    fcgi_server *s = (fcgi_server *) ap_pcalloc(p, sizeof(fcgi_server));

    /* Initialize anything who's init state is not zeroizzzzed */
    s->listenQueueDepth = FCGI_DEFAULT_LISTEN_Q;
    s->appConnectTimeout = FCGI_DEFAULT_APP_CONN_TIMEOUT;
    s->idle_timeout = FCGI_DEFAULT_IDLE_TIMEOUT;
    s->initStartDelay = DEFAULT_INIT_START_DELAY;
    s->restartDelay = FCGI_DEFAULT_RESTART_DELAY;
    s->restartOnExit = FALSE;
    s->directive = APP_CLASS_UNKNOWN;
    s->processPriority = FCGI_DEFAULT_PRIORITY;
#ifdef WIN32
    s->listenFd = (int)INVALID_HANDLE_VALUE;
#else
    s->listenFd = -2;
#endif
    s->envp = &fcgi_empty_env;

    return s;
}

/*******************************************************************************
 * Add the server to the linked list of FastCGI servers.
 */
void 
fcgi_util_fs_add(fcgi_server *s)
{
    s->next = fcgi_servers;
    fcgi_servers = s;
}

/*******************************************************************************
 * Configure uid, gid, user, group, username for suexec.
 */
const char *
fcgi_util_fs_set_uid_n_gid(pool *p, fcgi_server *s, uid_t uid, gid_t gid)
{
#ifndef WIN32
    struct passwd *pw;
    struct group  *gr;
#endif

    if (fcgi_suexec == NULL)
        return NULL;

#ifndef WIN32
    s->uid = uid;
    pw = getpwuid(uid);
    if (pw == NULL) {
        return ap_psprintf(p,
            "getpwuid() couldn't determine the username for uid '%ld', "
            "you probably need to modify the User directive: %s",
            (long)uid, strerror(errno));
    }
    s->user = ap_pstrdup(p, pw->pw_name);
    s->username = s->user;

    s->gid = gid;
    gr = getgrgid(gid);
    if (gr == NULL) {
        return ap_psprintf(p,
            "getgrgid() couldn't determine the group name for gid '%ld', "
            "you probably need to modify the Group directive: %s",
            (long)gid, strerror(errno));
    }
    s->group = ap_pstrdup(p, gr->gr_name);
#endif
    return NULL;
}

/*******************************************************************************
 * Allocate an array of ServerProcess records.
 */
ServerProcess *
fcgi_util_fs_create_procs(pool *p, int num)
{
    int i;
    ServerProcess *proc = (ServerProcess *)ap_pcalloc(p, sizeof(ServerProcess) * num);

    for (i = 0; i < num; i++) {
#ifdef WIN32
        proc[i].pid = (HANDLE) 0;
#else
        proc[i].pid = 0;
#endif
        proc[i].state = STATE_READY;
    }
    return proc;
}

/*
 *----------------------------------------------------------------------
 *
 * fcgi_util_lock_fd
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

#ifndef WIN32
int 
fcgi_util_lock_fd(int fd, int cmd, int type, off_t offset, int whence, off_t len)
{
    int res = 0;
    struct flock lock;

    lock.l_type = type;       /* F_RDLCK, F_WRLCK, F_UNLCK */
    lock.l_start = offset;    /* byte offset, relative to whence */
    lock.l_whence = whence;   /* SEEK_SET, SEET_CUR, SEEK_END */
    lock.l_len = len;         /* # of bytes, (0 indicates to EOF) */

    /* Don't be fooled into thinking we've set a lock when we've
       merely caught a signal.  */

    /* This is OK only if there is a hard_timeout() in effect! */
    while ((res = fcntl(fd, cmd, &lock)) == -1 && errno == EINTR);
    return res;
}
#endif    

int fcgi_util_gettimeofday(struct timeval *Time) {
#ifdef WIN32
    DWORD clock;
    time_t t;

    clock = GetTickCount();

    t = time(NULL);

    Time->tv_sec = t; //clock / 1000;
    Time->tv_usec = (clock - Time->tv_sec) * 1000;

    if (Time->tv_sec == (time_t)-1) 
        return -1;
    else
        return 0;
#else
    return gettimeofday(Time, NULL);
#endif
}

#ifdef WIN32

FcgiRWLock * fcgi_rdwr_create() {
	FcgiRWLock *newlock = NULL;

	newlock = (FcgiRWLock *) malloc(sizeof(FcgiRWLock));

	if (newlock == NULL)
		return NULL;

	newlock->read_event = CreateEvent(NULL, TRUE, FALSE, NULL);
	newlock->lock_mutex = CreateEvent(NULL, FALSE, TRUE, NULL);
	newlock->write_event = CreateMutex(NULL, FALSE, NULL);
	newlock->counter = -1;

	return newlock;
}

void fcgi_rdwr_destroy(FcgiRWLock *lock) {
	CloseHandle(lock->read_event);
	CloseHandle(lock->lock_mutex);
	CloseHandle(lock->write_event);

	free(lock);
	lock = NULL;
}


int fcgi_rdwr_lock(FcgiRWLock *lock, int type) {
	
	if (lock == NULL)
		return -1;

	if (type == WRITER) {  
		WaitForSingleObject(lock->write_event,INFINITE);
		WaitForSingleObject(lock->lock_mutex, INFINITE);
	}
	else {   
		if (InterlockedIncrement(&lock->counter) == 0) { 
			WaitForSingleObject(lock->lock_mutex, INFINITE);
			SetEvent(lock->read_event);
		}

		WaitForSingleObject(lock->read_event,INFINITE);
	}

	return 0;
}

int fcgi_rdwr_try_lock(FcgiRWLock *lock, int type) {
	DWORD dwret;
	
	if (lock == NULL)
		return -1;

	if (type == WRITER) {  
		dwret = WaitForSingleObject(lock->write_event, 0);
		if (dwret == WAIT_TIMEOUT)
			return -1;

		dwret = WaitForSingleObject(lock->lock_mutex, 0);
		if (dwret == WAIT_TIMEOUT)
			return -1;
	}
	else {   
		if (InterlockedIncrement(&lock->counter) == 0) { 
			dwret = WaitForSingleObject(lock->lock_mutex, 0);
			if (dwret == WAIT_TIMEOUT)
				return -1;

			SetEvent(lock->read_event);
		}

		dwret = WaitForSingleObject(lock->read_event, 0);
		if (dwret == WAIT_TIMEOUT)
			return -1;
	}

	return 0;
}

int fcgi_rdwr_unlock(FcgiRWLock *lock, int type) {

	if (type == WRITER) { 
		SetEvent(lock->lock_mutex);
	    ReleaseMutex(lock->write_event);
	}
	else {
		if (InterlockedDecrement(&lock->counter) < 0) {
			ResetEvent(lock->read_event);
			SetEvent(lock->lock_mutex);
		}
	}

	return 0;
}
#endif
