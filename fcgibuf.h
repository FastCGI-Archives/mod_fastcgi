/*
 * fcgibuf.h
 *
 * This file provides interface for the buffer library.
 */

#ifndef _FCGIBUF_H_
#define _FCGIBUF_H_

/*
 * This structure implements ring buffers, used to buffer data between
 * various processes and connections in the server.
 */
typedef struct Buffer {
    int size;               /* size of entire buffer */
    int length;             /* number of bytes in current buffer */
    char *begin;            /* begining of valid data */
    char *end;              /* end of valid data */
    char data[1];           /* buffer data */
} Buffer;

/*
 * Size of the ring buffers used to read/write the FastCGI application server.
 */
#define SERVER_BUFSIZE      8192
#define BufferLength(b)     ((b)->length)
#define BufferFree(b)       ((b)->size - (b)->length)
#define BufferSize(b)       ((b)->size)

/* function definitions */
void BufferCheck(Buffer *bufPtr);
void BufferReset(Buffer *bufPtr);
Buffer *BufferCreate(int size);
void BufferDelete(Buffer *bufPtr);
int BufferRead(Buffer *bufPtr, int fd);
int BufferWrite(Buffer *bufPtr, int fd);
void BufferPeekToss(Buffer *bufPtr, char **beginPtr, int *countPtr);
void BufferToss(Buffer *bufPtr, int count);
void BufferPeekExpand(Buffer *bufPtr, char **endPtr, int *countPtr);
void BufferExpand(Buffer *bufPtr, int count);
int BufferAddData(Buffer *bufPtr, char *data, int datalen);
int BufferAdd(Buffer *bufPtr, char *str);
int BufferGetData(Buffer *bufPtr, char *data, int datalen);
void BufferMove(Buffer *toPtr, Buffer *fromPtr, int len);
void BufferDStringAppend(DString *strPtr, Buffer *bufPtr, int len);

#endif
