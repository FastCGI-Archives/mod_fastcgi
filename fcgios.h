/*
 * fcgios.h
 *
 * Header file for OS abstraction layer.
 */

#ifndef _FCGIOS_H_
#define _FCGIOS_H_

int OS_Bind(unsigned int sock, struct sockaddr *addr, int namelen);
int OS_Listen(unsigned int sock, int backlog);
int OS_Socket(int addr_family, int type, int protocol);
int OS_Close(int fd);
int OS_Dup2(int oldd,int newd);
int OS_Read(int fd, void *buf,  size_t numBytes);
int OS_Write(int fd, void *buf, size_t numBytes);
Sigfunc *OS_Signal(int signo, Sigfunc *func);

#endif
