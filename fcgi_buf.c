/*
 * $Id: fcgi_buf.c,v 1.1 1999/02/09 03:07:59 roberts Exp $
 */

#include "fcgi.h"

/*******************************************************************************
 * Check buffer consistency with assertions.
 */
void fcgi_buf_check(Buffer *buf)
{
    ap_assert(buf->size > 0);
    ap_assert(buf->length >= 0);
    ap_assert(buf->length <= buf->size);

    ap_assert(buf->begin >= buf->data);
    ap_assert(buf->begin < buf->data + buf->size);
    ap_assert(buf->end >= buf->data);
    ap_assert(buf->end < buf->data + buf->size);

    ap_assert(((buf->end - buf->begin + buf->size) % buf->size)
            == (buf->length % buf->size));
}

/*******************************************************************************
 * Reset buffer, losing any data that's in it.
 */
void fcgi_buf_reset(Buffer *buf)
{
    buf->length = 0;
    buf->begin = buf->end = buf->data;
}

/*******************************************************************************
 * Allocate and intialize a new buffer of the specified size.
 */
Buffer *fcgi_buf_new(pool *p, int size)
{
    Buffer *buf;

    buf = (Buffer *)ap_pcalloc(p, sizeof(Buffer) + size);
    buf->size = size;
    fcgi_buf_reset(buf);
    return buf;
}

/*******************************************************************************
 * Read from an open file descriptor into buffer.
 *
 * The caller should disable the default Apache SIGPIPE handler,
 * otherwise a bad script could cause the request to abort and appear
 * as though the client's fd caused it.
 *
 * Results:
 *      <0 error, errno is set
 *      =0 EOF reached
 *      >0 successful read or no room in buffer (NOT # of bytes read)
 */
int fcgi_buf_add_fd(Buffer *buf, int fd)
{
    int len;

    fcgi_buf_check(buf);

    if (buf->length == buf->size)
        /* there's no room in the buffer, return "success" */
        return 1;

    if (buf->length == 0)
        /* the buffer is empty so defrag */
        buf->begin = buf->end = buf->data;

    len = min(buf->size - buf->length, buf->data + buf->size - buf->end);

#ifndef NO_WRITEV
    /* assume there is a readv() if there is a writev() */
    if (len == buf->size - buf->length) {
        /* its not wrapped, use read() instead of readv() */
#endif

    do
        len = read(fd, buf->end, len);
    while (len == -1 && errno == EINTR);

    if (len <= 0)
        return len;

    buf->end += len;
    buf->length += len;

    if (buf->end == (buf->data + buf->size)) {
        /* the buffer needs to be wrapped */
        buf->end = buf->data;
#ifndef NO_WRITEV
    }
    } else {
        /* the buffer is wrapped, use readv() */
        struct iovec vec[2];

        vec[0].iov_base = buf->end;
        vec[0].iov_len = len;
        vec[1].iov_base = buf->data;
        vec[1].iov_len = buf->size - buf->length - len;

        do
        len = readv(fd, vec, 2);
        while (len == -1 && errno == EINTR);

        if (len <= 0)
            return len;

        buf->end += len;
        if (buf->end >= (buf->data + buf->size))
            buf->end -= buf->size;

        buf->length += len;
    }
#else
        if (buf->length < buf->size) {
            /* There's still more buffer space to read into. */

            fd_set  read_set;
            int     status;
            int     numFDs = fd + 1;
            struct timeval timeOut;

            FD_ZERO(&read_set);
            FD_SET(fd, &read_set);

            timeOut.tv_sec = 0;
            timeOut.tv_usec = 0;

            status = ap_select(numFDs, &read_set, NULL, NULL, &timeOut);

            if (status < 0)
                return status;  /* error, errno is set */

            if (status > 0 && FD_ISSET(fd, &read_set)) {

                do
                len = read(fd, buf->end, buf->size - buf->length);
                while (len == -1 && errno == EINTR);

                if (len <= 0)
                    return len;

                buf->end += len;
                buf->length += len;
            }
        }
    }
#endif
    return len;     /* this may not contain the number of bytes read */
}

/*******************************************************************************
 * Write from the buffer to an open file descriptor.
 *
 * The caller should disable the default Apache SIGPIPE handler,
 * otherwise a bad script could cause the request to abort appearing
 * as though the client's fd caused it.
 *
 * Results:
 *      <0 if an error occured (bytes may or may not have been written)
 *      =0 if no bytes were written
 *      >0 successful write
 */
int fcgi_buf_get_to_fd(Buffer *buf, int fd)
{
    int len;

    fcgi_buf_check(buf);

    if (buf->length == 0)
        return 0;

    len = min(buf->length, buf->data + buf->size - buf->begin);

#ifndef NO_WRITEV
    if (len == buf->length) {
        /* the buffer is not wrapped, we don't need to use writev() */
#endif

    do
        len = write(fd, buf->begin, len);
    while (len == -1 && errno == EINTR);

    if (len <= 0)
        goto Return;

    buf->begin += len;
    buf->length -= len;

    if (buf->begin == buf->data + buf->size) {
        /* the buffer needs to be wrapped */
        buf->begin = buf->data;

#ifndef NO_WRITEV
    }
    } else {
        /* the buffer is wrapped, use writev() */
        struct iovec vec[2];

        vec[0].iov_base = buf->begin;
        vec[0].iov_len = len;
        vec[1].iov_base = buf->data;
        vec[1].iov_len = buf->length - len;

        do
        len = writev(fd, vec, 2);
        while (len == -1 && errno == EINTR);

        if (len <= 0)
            goto Return;

        buf->begin += len;
        buf->length -= len;

        if (buf->begin >= buf->data + buf->size)
            buf->begin -= buf->size;
    }
#else
        if (buf->length > 0) {
            /* there's still more data to write */

            fd_set  write_set;
            int     status;
            int     numFDs = fd + 1;
            struct timeval timeOut;

            FD_ZERO(&write_set);
            FD_SET(fd, &write_set);

            timeOut.tv_sec = 0;
            timeOut.tv_usec = 0;

            status = ap_select(numFDs, NULL, &write_set, NULL, &timeOut);

            if (status < 0) {
                len = status;  /* error, errno is set */
                goto Return;
            }

            if (status > 0 && FD_ISSET(fd, &write_set)) {
                int len2;

                do
                len2 = write(fd, buf->begin, buf->length);
                while (len == -1 && errno == EINTR);

                if (len2 < 0) {
                    len = len2;
                    goto Return;
                }

                if (len2 > 0) {
                    buf->begin += len2;
                    buf->length -= len2;
                    len += len2;
                }
            }
        }
    }
#endif

Return:
    if (buf->length == 0)
        buf->begin = buf->end = buf->data;

    return len;
}

/*******************************************************************************
 * Return the data block start address and the length of the block.
 */
void fcgi_buf_get_block_info(Buffer *buf, char **beginPtr, int *countPtr)
{
    fcgi_buf_check(buf);
    *beginPtr = buf->begin;
    *countPtr = min(buf->length,
                    buf->data + buf->size - buf->begin);
}

/*******************************************************************************
 * Throw away bytes from buffer.
 */
void fcgi_buf_toss(Buffer *buf, int count)
{
    fcgi_buf_check(buf);
    ap_assert(count >= 0 && count <= buf->length);

    buf->length -= count;
    buf->begin += count;
    if(buf->begin >= buf->data + buf->size) {
        buf->begin -= buf->size;
    }
}

/*******************************************************************************
 * Return the free data block start address and the length of the block.
 */
void fcgi_buf_get_free_block_info(Buffer *buf, char **endPtr, int *countPtr)
{
    fcgi_buf_check(buf);
    *endPtr = buf->end;
    *countPtr = min(buf->size - buf->length,
                    buf->data + buf->size - buf->end);
}

/*******************************************************************************
 * Updates the buf to reflect recently added data.
 */
void fcgi_buf_add_update(Buffer *buf, int count)
{
    fcgi_buf_check(buf);
    ap_assert(count >= 0 && count <= BufferFree(buf));

    buf->length += count;
    buf->end += count;
    if(buf->end >= buf->data + buf->size) {
        buf->end -= buf->size;
    }

    fcgi_buf_check(buf);
}

/*******************************************************************************
 * Adds a block of data to a buffer, returning the number of bytes added.
 */
int fcgi_buf_add_block(Buffer *buf, char *data, int datalen)
{
    char *end;
    int copied = 0;     /* Number of bytes actually copied. */
    int canCopy;                /* Number of bytes to copy in a given op. */

    ap_assert(data != NULL);
    if(datalen == 0) {
        return 0;
    }

    ap_assert(datalen > 0);
    fcgi_buf_check(buf);
    end = buf->data + buf->size;

    /*
     * Copy the first part of the data:  from here to the end of the
     * buffer, or the end of the data, whichever comes first.
     */
    datalen = min(BufferFree(buf), datalen);
    canCopy = min(datalen, end - buf->end);
    memcpy(buf->end, data, canCopy);
    buf->length += canCopy;
    buf->end += canCopy;
    copied += canCopy;
    if (buf->end >= end) {
        buf->end = buf->data;
    }
    datalen -= canCopy;

    /*
     * If there's more to go, copy the second part starting from the
     * beginning of the buffer.
     */
    if (datalen > 0) {
        data += canCopy;
        memcpy(buf->end, data, datalen);
        buf->length += datalen;
        buf->end += datalen;
        copied += datalen;
    }
    return(copied);
}

/*******************************************************************************
 * Add a string to a buffer, returning the number of bytes added.
 */
int fcgi_buf_add_string(Buffer *buf, char *str)
{
    return fcgi_buf_add_block(buf, str, strlen(str));
}

/*******************************************************************************
 * Gets a data block from a buffer, returning the number of bytes copied.
 */
int fcgi_buf_get_to_block(Buffer *buf, char *data, int datalen)
{
    char *end;
    int copied = 0;                /* Number of bytes actually copied. */
    int canCopy;                   /* Number of bytes to copy in a given op. */

    ap_assert(data != NULL);
    ap_assert(datalen > 0);
    fcgi_buf_check(buf);
    end = buf->data + buf->size;

    /*
     * Copy the first part out of the buffer: from here to the end
     * of the buffer, or all of the requested data.
     */
    canCopy = min(buf->length, datalen);
    canCopy = min(canCopy, end - buf->begin);
    memcpy(data, buf->begin, canCopy);
    buf->length -= canCopy;
    buf->begin += canCopy;
    copied += canCopy;
    if (buf->begin >= end) {
        buf->begin = buf->data;
    }

    /*
     * If there's more to go, copy the second part starting from the
     * beginning of the buffer.
     */
    if (copied < datalen && buf->length > 0) {
        data += copied;
        canCopy = min(buf->length, datalen - copied);
        memcpy(data, buf->begin, canCopy);
        buf->length -= canCopy;
        buf->begin += canCopy;
        copied += canCopy;
    }
    fcgi_buf_check(buf);
    return(copied);
}

/*******************************************************************************
 * Move 'len' bytes from 'src' buffer to 'dest' buffer.  There must be at
 * least 'len' bytes available in the source buffer and space for 'len'
 * bytes in the destination buffer.
 */
void fcgi_buf_get_to_buf(Buffer *dest, Buffer *src, int len)
{
    char *dest_end, *src_begin;
    int dest_len, src_len, move_len;

    ap_assert(len > 0);
    ap_assert(BufferLength(src) >= len);
    ap_assert(BufferFree(dest) >= len);

    fcgi_buf_check(src);
    fcgi_buf_check(dest);

    while (1) {
        if (len == 0)
            return;

        fcgi_buf_get_free_block_info(dest, &dest_end, &dest_len);
        fcgi_buf_get_block_info(src, &src_begin, &src_len);

        move_len = min(dest_len, src_len);
        move_len = min(move_len, len);

        if (move_len == 0)
            return;

        memcpy(dest_end, src_begin, move_len);
        fcgi_buf_toss(src, move_len);
        fcgi_buf_add_update(dest, move_len);
        len -= move_len;
    }
}


static void array_grow(array_header *arr, int n)
{
    if (n <= 0)
        return;
    if (arr->nelts + n > arr->nalloc) {
        char *new_data;
        int new_size = (arr->nalloc <= 0) ? : arr->nalloc * 2;

        while (arr->nelts + n > new_size)
            new_size *= 2;

        new_data = ap_pcalloc(arr->pool, arr->elt_size * new_size);
        memcpy(new_data, arr->elts, arr->nelts * arr->elt_size);
        arr->elts = new_data;
        arr->nalloc = new_size;
    }
}

static void array_cat_block(array_header *arr, void *block, int n)
{
    array_grow(arr, n);
    memcpy(arr->elts + arr->nelts * arr->elt_size, block, n * arr->elt_size);
    arr->nelts += n;
}

/*----------------------------------------------------------------------
 * Append "len" bytes from "buf" into "arr".  Apache arrays are used
 * whenever the data being handled is binary (may contain null chars).
 */
void fcgi_buf_get_to_array(Buffer *buf, array_header *arr,  int len)
{
    int len1 = min(buf->length, buf->data + buf->size - buf->begin);

    fcgi_buf_check(buf);
    ap_assert(len > 0);
    ap_assert(len <= BufferLength(buf));

    array_grow(arr, len);

    len1 = min(len1, len);
    array_cat_block(arr, buf->begin, len1);

    if (len1 < len)
        array_cat_block(arr, buf->data, len - len1);

    fcgi_buf_toss(buf, len);
}
