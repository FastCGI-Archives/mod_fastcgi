/*
 * fcgibuf.c
 * 
 * Ring buffer library.
 *
 * $Id: fcgibuf.c,v 1.2 1998/02/24 17:11:40 roy Exp $
 */

#include "conf.h"                       /* apache code */
#include "mod_fastcgi.h"
#include "fcgitcl.h"
#include "fcgios.h"
#include "fcgibuf.h"

/*
 *----------------------------------------------------------------------
 *
 * BufferCheck --
 *
 *      Checks buffer for consistency with a set of assertions.
 *
 *      If assert() is a no-op, this routine should be optimized away
 *      in most C compilers.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

void BufferCheck(Buffer *bufPtr)
{
    ASSERT(bufPtr->size > 0);
    ASSERT(bufPtr->length >= 0);
    ASSERT(bufPtr->length <= bufPtr->size);

    ASSERT(bufPtr->begin >= bufPtr->data);
    ASSERT(bufPtr->begin < bufPtr->data + bufPtr->size);
    ASSERT(bufPtr->end >= bufPtr->data);
    ASSERT(bufPtr->end < bufPtr->data + bufPtr->size);

    ASSERT(((bufPtr->end - bufPtr->begin + bufPtr->size) % bufPtr->size) 
            == (bufPtr->length % bufPtr->size));
}

/*
 *----------------------------------------------------------------------
 *
 * BufferReset --
 *
 *      Reset a buffer, losing any data that's in it.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

void BufferReset(Buffer *bufPtr)
{
    bufPtr->length = 0;
    bufPtr->begin = bufPtr->end = bufPtr->data;
}

/*
 *----------------------------------------------------------------------
 *
 * BufferCreate --
 *
 *      Allocate an intialize a new buffer of the specified size.
 *
 * Results:
 *      Pointer to newly allocated buffer.
 *
 * Side effects:
 *      None.                     
 *
 *----------------------------------------------------------------------
 */

Buffer *BufferCreate(int size)
{
    Buffer *bufPtr;

    bufPtr = (Buffer *)Malloc(sizeof(Buffer) + size);
    bufPtr->size = size;
    BufferReset(bufPtr);
    return bufPtr;
}

/*
 *----------------------------------------------------------------------
 *
 * BufferDelete --
 *
 *      Delete a buffer, freeing up any associated storage.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

void BufferDelete(Buffer *bufPtr)
{
    BufferCheck(bufPtr);
    Free(bufPtr);
}

/*
 *----------------------------------------------------------------------
 *
 * BufferRead --
 *
 *      Read bytes from an open file descriptor into a buffer.
 *
 * Results:
 *      Returns number of bytes read.
 *
 * Side effects:
 *      Data stored in buffer.
 *
 *----------------------------------------------------------------------
 */

int BufferRead(Buffer *bufPtr, int fd)
{
    int len;

    BufferCheck(bufPtr);
    len = min(bufPtr->size - bufPtr->length, 
            bufPtr->data + bufPtr->size - bufPtr->end);

    if (len > 0) {
        OS_Signal(SIGPIPE, SIG_IGN);
        len = OS_Read(fd, bufPtr->end, len);
        if(len > 0) {
            bufPtr->end += len;
            if(bufPtr->end >= (bufPtr->data + bufPtr->size)) {
                bufPtr->end -= bufPtr->size;
	    }
            bufPtr->length += len;
        }
    }
    return len;
}

/*
 *----------------------------------------------------------------------
 *
 * BufferWrite --
 *
 *      Write any bytes from the buffer to a file descriptor open for
 *      writing.
 *
 * Results:
 *      Returns number of bytes written.
 *
 * Side effects:
 *      Data "removed" from buffer.
 *
 *----------------------------------------------------------------------
 */

int BufferWrite(Buffer *bufPtr, int fd)
{
    int len;

    ASSERT(fd >= 0);
    BufferCheck(bufPtr);
    len = min(bufPtr->length, bufPtr->data + bufPtr->size - bufPtr->begin);

    if(len > 0) {
        len = OS_Write(fd, bufPtr->begin, len);
        if(len > 0) {
            bufPtr->begin += len;
            if(bufPtr->begin >= (bufPtr->data + bufPtr->size)) {
                bufPtr->begin -= bufPtr->size;
	    }
            bufPtr->length -= len;
        }
    }
    return len;
}

/*
 *----------------------------------------------------------------------
 *
 * BufferPeekToss --
 *
 *      Return (via pointer parameters) a pointer to the first occupied
 *      byte in the buffer, and a count of the number of sequential
 *      occupied bytes starting with that byte.  The caller can access
 *      these bytes as long as BufferWrite, BufferToss, etc are not
 *      called.
 *
 * Results:
 *      *beginPtr (first occupied byte) and *countPtr (byte count).
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

void BufferPeekToss(Buffer *bufPtr, char **beginPtr, int *countPtr)
{
    BufferCheck(bufPtr);
    *beginPtr = bufPtr->begin;
    *countPtr = min(bufPtr->length,
                    bufPtr->data + bufPtr->size - bufPtr->begin);
}

/*
 *----------------------------------------------------------------------
 *
 * BufferToss --
 *
 *      Throw away the specified number of bytes from a buffer, as if
 *      they had been written out.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      Data "removed" from the buffer.
 *
 *----------------------------------------------------------------------
 */

void BufferToss(Buffer *bufPtr, int count)
{
    BufferCheck(bufPtr);
    ASSERT(count >= 0 && count <= bufPtr->length);

    bufPtr->length -= count;
    bufPtr->begin += count;
    if(bufPtr->begin >= bufPtr->data + bufPtr->size) {
        bufPtr->begin -= bufPtr->size;
    }
}

/*
 *----------------------------------------------------------------------
 *
 * BufferPeekExpand --
 *
 *      Return (via pointer parameters) a pointer to the first free byte
 *      in the buffer, and a count of the number of sequential free bytes
 *      available starting with that byte.  The caller can write
 *      these bytes as long as BufferRead, BufferExpand, etc are
 *      not called.
 *
 * Results:
 *      *endPtr (first free byte) and *countPtr (byte count).
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

void BufferPeekExpand(Buffer *bufPtr, char **endPtr, int *countPtr)
{
    BufferCheck(bufPtr);
    *endPtr = bufPtr->end;
    *countPtr = min(bufPtr->size - bufPtr->length, 
                    bufPtr->data + bufPtr->size - bufPtr->end);
}

/*
 *----------------------------------------------------------------------
 *
 * BufferExpand --
 *
 *      Expands the buffer by the specified number of bytes.  Assumes that
 *      the caller has added the data to the buffer.  This is typically
 *      used after a BufferAsyncRead() call completes, to update the buffer
 *      size with the number of bytes read.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      Data "added" to the buffer.
 *
 *----------------------------------------------------------------------
 */

void BufferExpand(Buffer *bufPtr, int count)
{
    BufferCheck(bufPtr);
    ASSERT(count >= 0 && count <= BufferFree(bufPtr));

    bufPtr->length += count;
    bufPtr->end += count;
    if(bufPtr->end >= bufPtr->data + bufPtr->size) {
        bufPtr->end -= bufPtr->size;
    }

    BufferCheck(bufPtr);
}

/*
 *----------------------------------------------------------------------
 *
 * BufferAddData --
 *
 *      Adds data to a buffer, returning the number of bytes added.
 *
 * Results:
 *      Number of bytes added to the buffer.
 *
 * Side effects:
 *      Characters added to the buffer.
 *
 *----------------------------------------------------------------------
 */

int BufferAddData(Buffer *bufPtr, char *data, int datalen)
{
    char *end;
    int copied = 0;     /* Number of bytes actually copied. */
    int canCopy;                /* Number of bytes to copy in a given op. */

    ASSERT(data != NULL);
    if(datalen == 0) {
        return 0;
    }

    ASSERT(datalen > 0);
    BufferCheck(bufPtr);
    end = bufPtr->data + bufPtr->size;

    /*
     * Copy the first part of the data:  from here to the end of the
     * buffer, or the end of the data, whichever comes first.
     */
    datalen = min(BufferFree(bufPtr), datalen);
    canCopy = min(datalen, end - bufPtr->end);
    memcpy(bufPtr->end, data, canCopy);
    bufPtr->length += canCopy;
    bufPtr->end += canCopy;
    copied += canCopy;
    if (bufPtr->end >= end) {
        bufPtr->end = bufPtr->data;
    }
    datalen -= canCopy;

    /*
     * If there's more to go, copy the second part starting from the
     * beginning of the buffer.
     */
    if (datalen > 0) {
        data += canCopy;
        memcpy(bufPtr->end, data, datalen);
        bufPtr->length += datalen;
        bufPtr->end += datalen;
        copied += datalen;
    }
    return(copied);
}

/*
 *----------------------------------------------------------------------
 *
 * BufferAdd --
 *
 *      Adds a string into a buffer, returning the number of bytes added.
 *
 * Results:
 *      Number of bytes added to the buffer.
 *
 * Side effects:
 *      Characters added to the buffer.
 *
 *----------------------------------------------------------------------
 */

int BufferAdd(Buffer *bufPtr, char *str)
{
    return BufferAddData(bufPtr, str, strlen(str));
}

/*
 *----------------------------------------------------------------------
 *
 * BufferGetData --
 *
 *      Gets data from a buffer, returning the number of bytes copied.
 *
 * Results:
 *      Number of bytes copied from the buffer.
 *
 * Side effects:
 *      Updates the buffer pointer.
 *
 *----------------------------------------------------------------------
 */

int BufferGetData(Buffer *bufPtr, char *data, int datalen)
{
    char *end;
    int copied = 0;                /* Number of bytes actually copied. */
    int canCopy;                   /* Number of bytes to copy in a given op. */

    ASSERT(data != NULL);
    ASSERT(datalen > 0);
    BufferCheck(bufPtr);
    end = bufPtr->data + bufPtr->size;

    /*
     * Copy the first part out of the buffer: from here to the end
     * of the buffer, or all of the requested data.
     */
    canCopy = min(bufPtr->length, datalen);
    canCopy = min(canCopy, end - bufPtr->begin);
    memcpy(data, bufPtr->begin, canCopy);
    bufPtr->length -= canCopy;
    bufPtr->begin += canCopy;
    copied += canCopy;
    if (bufPtr->begin >= end) {
        bufPtr->begin = bufPtr->data;
    }

    /*
     * If there's more to go, copy the second part starting from the
     * beginning of the buffer.
     */
    if (copied < datalen && bufPtr->length > 0) {
        data += copied;
        canCopy = min(bufPtr->length, datalen - copied);
        memcpy(data, bufPtr->begin, canCopy);
        bufPtr->length -= canCopy;
        bufPtr->begin += canCopy;
        copied += canCopy;
    }
    BufferCheck(bufPtr);
    return(copied);
}

/*
 *----------------------------------------------------------------------
 *
 * BufferMove --
 *
 *      Move the specified number of bytes from one buffer to another.
 *      There must be at least 'len' bytes available in the source buffer,
 *      and space for 'len' bytes in the destination buffer.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      Bytes moved.
 *
 *----------------------------------------------------------------------
 */

void BufferMove(Buffer *toPtr, Buffer *fromPtr, int len)
{
    int fromLen, toLen, toMove;
    
    ASSERT(len > 0);
    ASSERT(BufferLength(fromPtr) >= len);
    ASSERT(BufferFree(toPtr) >= len);

    BufferCheck(toPtr);
    BufferCheck(fromPtr);

    for(;;) {
        fromLen = min(fromPtr->length, 
                fromPtr->data + fromPtr->size - fromPtr->begin);

        toLen = min(toPtr->size - toPtr->length, 
                toPtr->data + toPtr->size - toPtr->end);

        toMove = min(fromLen, toLen);
        toMove = min(toMove, len);

        ASSERT(toMove >= 0);
        if(toMove == 0) {
            return;
	}

        memcpy(toPtr->end, fromPtr->begin, toMove);
        BufferToss(fromPtr, toMove);
        BufferExpand(toPtr, toMove);
        len -= toMove;
    }
}

/*
 *----------------------------------------------------------------------
 *
 * BufferDStringAppend --
 *
 *      Append the specified number of bytes from a buffer onto the 
 *      end of a DString.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      Bytes moved.
 *
 *----------------------------------------------------------------------
 */

void BufferDStringAppend(DString *strPtr, Buffer *bufPtr, int len)
{
    int fromLen;

    BufferCheck(bufPtr);
    ASSERT(len > 0);
    ASSERT(len <= BufferLength(bufPtr));

    while(len > 0) {
        fromLen = min(len, bufPtr->data + bufPtr->size - bufPtr->begin);

        ASSERT(fromLen > 0);
        DStringAppend(strPtr, bufPtr->begin, fromLen);
        BufferToss(bufPtr, fromLen);
        len -= fromLen;
    }
}
