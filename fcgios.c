/*
 * fcgios.c
 *
 * OS abstraction layer - well, not really
 */

#include "conf.h"                       /* apache code */
#include "mod_fastcgi.h"
#include "fcgios.h"

int OS_Bind(unsigned int sock, struct sockaddr *addr, int namelen)
{
    return(bind(sock, addr, namelen));
}

int OS_Listen(unsigned int sock, int backlog)
{
    return(listen(sock, backlog));
}

int OS_Socket(int addr_family, int type, int protocol)
{
    return (socket(addr_family, type, protocol));
}

int OS_Close(int fd)
{
    return close(fd);
}

int OS_Dup2(int oldd,int newd)
{
    int fd;

    fd = dup2(oldd, newd);
    return fd;
}

int OS_Read(int fd, void *buf, size_t numBytes)
{
    int result;

    while (1) {
        result = read(fd, buf, (size_t) numBytes);
        if ((result != -1) || (errno != EINTR)) {
            return result;
        }
    }
}

int OS_Write(int fd, void *buf, size_t numBytes)
{
    int result;

    while (1) {
        result = write(fd, buf, (size_t) numBytes);
        if ((result != -1) || (errno != EINTR)) {
            return result;
        }
    }
}

/*
 *----------------------------------------------------------------------
 *
 * OS_Signal --
 *
 *      Reliable implementation of the Posix signal function
 *      Makes no attempt either to restart or to prevent restart
 *      of system calls.
 *
 *----------------------------------------------------------------------
 */

Sigfunc *OS_Signal(int signo, Sigfunc *func)
{
    struct sigaction act, oact;
    act.sa_handler = func;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    if(sigaction(signo, &act, &oact) < 0) {
        return(SIG_ERR);
    }
    return oact.sa_handler;
}
