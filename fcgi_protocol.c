/*
 * $Id: fcgi_protocol.c,v 1.10 1999/09/24 02:26:28 roberts Exp $
 */


#include "fcgi.h"
#include "fcgi_protocol.h"

 /*******************************************************************************
 * Build and queue a FastCGI message header.  It is the caller's
 * responsibility to make sure that there's enough space in the buffer, and
 * that the data bytes (specified by 'len') are queued immediately following
 * this header.
 */
static void queue_header(fcgi_request *fr, int type, int len)
{
    FCGI_Header header;

    ap_assert(type > 0 && type <= FCGI_MAXTYPE);
    ap_assert(len >= 0 && len <= 0xffff);
    ap_assert(BufferFree(fr->serverOutputBuffer) > sizeof(FCGI_Header));

    /* Assemble and queue the packet header. */
    header.version = FCGI_VERSION;
    header.type = type;
    header.requestIdB1 = (fr->requestId >> 8) & 0xff;
    header.requestIdB0 = (fr->requestId) & 0xff;
    header.contentLengthB1 = len/256;  /* MSB */
    header.contentLengthB0 = len%256;  /* LSB */
    header.paddingLength = 0;
    header.reserved = 0;
    fcgi_buf_add_block(fr->serverOutputBuffer, (char *) &header, sizeof(FCGI_Header));
}

/*******************************************************************************
 * Build a FCGI_BeginRequest message body.
 */
static void build_begin_request(int role, int keepConnection,
        FCGI_BeginRequestBody *body)
{
    ap_assert((role >> 16) == 0);
    body->roleB1 = (role >>  8) & 0xff;
    body->roleB0 = (role      ) & 0xff;
    body->flags = (keepConnection) ? FCGI_KEEP_CONN : 0;
    memset(body->reserved, 0, sizeof(body->reserved));
}

/*******************************************************************************
 * Build and queue a FastCGI "Begin Request" message.
 */
void fcgi_protocol_queue_begin_request(fcgi_request *fr)
{
    FCGI_BeginRequestBody body;
    int bodySize = sizeof(FCGI_BeginRequestBody);

    /* We should be the first ones to use this buffer */
    ap_assert(BufferLength(fr->serverOutputBuffer) == 0);

    build_begin_request(fr->role, FALSE, &body);
    queue_header(fr, FCGI_BEGIN_REQUEST, bodySize);
    fcgi_buf_add_block(fr->serverOutputBuffer, (char *) &body, bodySize);
}

/*******************************************************************************
 * Build a FastCGI name-value pair (env) header.
 */
static void build_env_header(int nameLen, int valueLen,
        unsigned char *headerBuffPtr, int *headerLenPtr)
{
    unsigned char *startHeaderBuffPtr = headerBuffPtr;

    ap_assert(nameLen >= 0);
    if(nameLen < 0x80) {
        *headerBuffPtr++ = nameLen;
    } else {
        *headerBuffPtr++ = (nameLen >> 24) | 0x80;
        *headerBuffPtr++ = (nameLen >> 16);
        *headerBuffPtr++ = (nameLen >> 8);
        *headerBuffPtr++ = nameLen;
    }
    ap_assert(valueLen >= 0);
    if(valueLen < 0x80) {
        *headerBuffPtr++ = valueLen;
    } else {
        *headerBuffPtr++ = (valueLen >> 24) | 0x80;
        *headerBuffPtr++ = (valueLen >> 16);
        *headerBuffPtr++ = (valueLen >> 8);
        *headerBuffPtr++ = valueLen;
    }
    *headerLenPtr = headerBuffPtr - startHeaderBuffPtr;
}

/* A static fn stolen from Apache's util_script.c...
 * Obtain the Request-URI from the original request-line, returning
 * a new string from the request pool containing the URI or "".
 */
static char *apache_original_uri(request_rec *r)
{
    char *first, *last;

    if (r->the_request == NULL)
        return (char *) ap_pcalloc(r->pool, 1);

    first = r->the_request;	/* use the request-line */

    while (*first && !ap_isspace(*first))
        ++first;		    /* skip over the method */

    while (ap_isspace(*first))
        ++first;		    /* and the space(s) */

    last = first;
    while (*last && !ap_isspace(*last))
        ++last;			    /* end at next whitespace */

    return ap_pstrndup(r->pool, first, last - first);
}

/* Based on Apache's ap_add_cgi_vars() in util_script.c.
 * Apache's spins in sub_req_lookup_uri() trying to setup PATH_TRANSLATED,
 * so we just don't do that part.
 */
static void add_auth_cgi_vars(request_rec *r, const int compat)
{
    table *e = r->subprocess_env;

    ap_table_setn(e, "GATEWAY_INTERFACE", "CGI/1.1");
    ap_table_setn(e, "SERVER_PROTOCOL", r->protocol);
    ap_table_setn(e, "REQUEST_METHOD", r->method);
    ap_table_setn(e, "QUERY_STRING", r->args ? r->args : "");
    ap_table_setn(e, "REQUEST_URI", apache_original_uri(r));

    /* The FastCGI spec precludes sending of CONTENT_LENGTH, PATH_INFO,
     * PATH_TRANSLATED, and SCRIPT_NAME (for some reason?).  PATH_TRANSLATED we
     * don't have, its the variable that causes Apache to break trying to set
     * up (and thus the reason this fn exists vs. using ap_add_cgi_vars()). */
    if (compat) {
        ap_table_unset(e, "CONTENT_LENGTH");
        return;
    }

    /* Note that the code below special-cases scripts run from includes,
     * because it "knows" that the sub_request has been hacked to have the
     * args and path_info of the original request, and not any that may have
     * come with the script URI in the include command.  Ugh. */
    if (!strcmp(r->protocol, "INCLUDED")) {
        ap_table_setn(e, "SCRIPT_NAME", r->uri);
        if (r->path_info && *r->path_info)
            ap_table_setn(e, "PATH_INFO", r->path_info);
    }
    else if (!r->path_info || !*r->path_info)
        ap_table_setn(e, "SCRIPT_NAME", r->uri);
    else {
        int path_info_start = ap_find_path_info(r->uri, r->path_info);

        ap_table_setn(e, "SCRIPT_NAME", ap_pstrndup(r->pool, r->uri, path_info_start));
        ap_table_setn(e, "PATH_INFO", r->path_info);
    }
}

static void add_pass_header_vars(fcgi_request *fr)
{
    const array_header *ph = fr->dynamic ? dynamic_pass_headers : fr->fs->pass_headers;

    if (ph) {
        const char **elt = (const char **)ph->elts;
        int i = ph->nelts;

        for ( ; i; --i, ++elt) {
            const char *val = ap_table_get(fr->r->headers_in, *elt);
            if (val) {
                ap_table_setn(fr->r->subprocess_env, *elt, val);
            }
        }
    }
}

/*******************************************************************************
 * Build and queue the environment name-value pairs.  Returns TRUE if the
 * complete ENV was buffered, FALSE otherwise.  Note: envp is updated to
 * reflect the current position in the ENV.
 */
int fcgi_protocol_queue_env(request_rec *r, fcgi_request *fr, char ***envp)
{
    static int              headerLen, nameLen, valueLen, totalLen;
    static char             *equalPtr;
    static unsigned char    headerBuff[8];
    static enum { prep, header, name, value } pass;
    int       charCount;

    if (*envp == NULL) {
        ap_add_common_vars(r);
        add_pass_header_vars(fr);

        if (fr->role == FCGI_RESPONDER)
	        ap_add_cgi_vars(r);
        else
            add_auth_cgi_vars(r, fr->auth_compat);

        *envp = ap_create_environment(r->pool, r->subprocess_env);
        pass = prep;
    }

    while (**envp) {
        switch (pass) {
            case prep:
                equalPtr = strchr(**envp, '=');
                ap_assert(equalPtr != NULL);
                nameLen = equalPtr - **envp;
                valueLen = strlen(++equalPtr);
                build_env_header(nameLen, valueLen, headerBuff, &headerLen);
                totalLen = headerLen + nameLen + valueLen;
                pass = header;
                /* drop through */
            case header:
                if (BufferFree(fr->serverOutputBuffer) < (sizeof(FCGI_Header)+headerLen)) {
                    return (FALSE);
                }
                queue_header(fr, FCGI_PARAMS, totalLen);
                fcgi_buf_add_block(fr->serverOutputBuffer, (char *)headerBuff, headerLen);
                pass = name;
                /* drop through */
            case name:
                charCount = fcgi_buf_add_block(fr->serverOutputBuffer, **envp, nameLen);
                if (charCount != nameLen) {
                    **envp += charCount;
                    nameLen -= charCount;
                    return (FALSE);
                }
                pass = value;
                /* drop through */
            case value:
                charCount = fcgi_buf_add_block(fr->serverOutputBuffer, equalPtr, valueLen);
                if (charCount != valueLen) {
                    equalPtr += charCount;
                    valueLen -= charCount;
                    return (FALSE);
                }
                pass = prep;
        }
        (*envp)++;
    }
    if (BufferFree(fr->serverOutputBuffer) < sizeof(FCGI_Header)) {
        return(FALSE);
    }
    queue_header(fr, FCGI_PARAMS, 0);
    return(TRUE);
}

/*******************************************************************************
 * Queue data from the client input buffer to the FastCGI server output
 * buffer (encapsulating the data in FastCGI protocol messages).
 */
void fcgi_protocol_queue_client_buffer(fcgi_request *fr)
{
    int movelen;
    int in_len, out_free;

    if (fr->eofSent)
        return;

    /*
     * If there's some client data and room for at least one byte
     * of data in the output buffer (after protocol overhead), then
     * move some data to the output buffer.
     */
    in_len = BufferLength(fr->clientInputBuffer);
    out_free = max(0, BufferFree(fr->serverOutputBuffer) - sizeof(FCGI_Header));
    movelen = min(in_len, out_free);
    if (movelen > 0) {
        queue_header(fr, FCGI_STDIN, movelen);
        fcgi_buf_get_to_buf(fr->serverOutputBuffer, fr->clientInputBuffer, movelen);
    }

    /*
     * If all the client data has been sent, and there's room
     * in the output buffer, indicate EOF.
     */
    if (movelen == in_len && fr->expectingClientContent <= 0
            && BufferFree(fr->serverOutputBuffer) >= sizeof(FCGI_Header))
    {
        queue_header(fr, FCGI_STDIN, 0);
        fr->eofSent = TRUE;
    }
}

/*******************************************************************************
 * Read FastCGI protocol messages from the FastCGI server input buffer into
 * fr->header when parsing headers, to fr->fs_stderr when reading stderr data,
 * or to the client output buffer otherwises.
 */
int fcgi_protocol_dequeue(pool *p, fcgi_request *fr)
{
    FCGI_Header header;
    int len;

    while (BufferLength(fr->serverInputBuffer) > 0) {
        /*
         * State #1:  looking for the next complete packet header.
         */
        if (fr->gotHeader == FALSE) {
            if (BufferLength(fr->serverInputBuffer) < sizeof(FCGI_Header)) {
                return OK;
            }
            fcgi_buf_get_to_block(fr->serverInputBuffer, (char *) &header,
                    sizeof(FCGI_Header));
            /*
             * XXX: Better handling of packets with other version numbers
             * and other packet problems.
             */
            if (header.version != FCGI_VERSION) {
                ap_log_rerror(FCGI_LOG_ERR_NOERRNO, fr->r,
                    "FastCGI: comm with server \"%s\" aborted: protocol error: invalid version: %d != FCGI_VERSION(%d)",
                    fr->fs_path, header.version, FCGI_VERSION);
                return SERVER_ERROR;
            }
            if (header.type > FCGI_MAXTYPE) {
                ap_log_rerror(FCGI_LOG_ERR_NOERRNO, fr->r,
                    "FastCGI: comm with server \"%s\" aborted: protocol error: invalid type: %d > FCGI_MAXTYPE(%d)",
                    fr->fs_path, header.type, FCGI_MAXTYPE);
                return SERVER_ERROR;
            }

            fr->packetType = header.type;
            fr->dataLen = (header.contentLengthB1 << 8)
                    + header.contentLengthB0;
            fr->gotHeader = TRUE;
            fr->paddingLen = header.paddingLength;
        }

        /*
         * State #2:  got a header, and processing packet bytes.
         */
        len = min(fr->dataLen, BufferLength(fr->serverInputBuffer));
        ap_assert(len >= 0);
        switch (fr->packetType) {
            case FCGI_STDOUT:
                if (len > 0) {
                    switch(fr->parseHeader) {
                        case SCAN_CGI_READING_HEADERS:
                            fcgi_buf_get_to_array(fr->serverInputBuffer, fr->header, len);
                            break;
                        case SCAN_CGI_FINISHED:
                            len = min(BufferFree(fr->clientOutputBuffer), len);
                            if (len > 0) {
                                fcgi_buf_get_to_buf(fr->clientOutputBuffer, fr->serverInputBuffer, len);
                            } else {
                                return OK;
                            }
                            break;
                        default:
                            /* Toss data on the floor */
                            break;
                    }
                    fr->dataLen -= len;
                }
                break;
            case FCGI_STDERR:
                if (len > 0) {
                    int max_len;
                    char *start_of_line, *end_of_line;

                    /* This doesn't have to be fast, its the exception */

                    if (fr->fs_stderr == NULL)
                        fr->fs_stderr = ap_pcalloc(p, FCGI_SERVER_MAX_STDERR_LINE_LEN + 1);

                    /* We're gonna consume all of it */
                    fr->dataLen -= len;

                    while ((max_len = min(len, FCGI_SERVER_MAX_STDERR_LINE_LEN - strlen(fr->fs_stderr)))) {
                        /* Put as much as we can in the block */
                        int cur_stderr_len = strlen(fr->fs_stderr);
                        fcgi_buf_get_to_block(fr->serverInputBuffer,
                            fr->fs_stderr + cur_stderr_len, max_len);
                        *(fr->fs_stderr + cur_stderr_len + max_len) = '\0';
                        len -= max_len;

                        /* Print as much as we can */
                        start_of_line = fr->fs_stderr;
                        while ((end_of_line = strpbrk(start_of_line, "\r\n"))) {
                            *end_of_line = '\0';
                            ap_log_rerror(FCGI_LOG_ERR_NOERRNO, fr->r,
                                "FastCGI: server \"%s\" stderr: %s", fr->fs_path, start_of_line);
                            ++end_of_line;
                            start_of_line = end_of_line + strspn(end_of_line, "\r\n");
                        }

                        /* Move any leftovers down */
                        if (*start_of_line && start_of_line != fr->fs_stderr) {
                            size_t move_len = strlen(start_of_line);

                            memmove(fr->fs_stderr, start_of_line, move_len);
                            *(fr->fs_stderr + move_len) = '\0';
                        }
                        else
                            *fr->fs_stderr = '\0';
                    }

                    if (len) {
                        ap_log_rerror(FCGI_LOG_ERR_NOERRNO, fr->r,
                            "FastCGI: server \"%s\" stderr: %s...", fr->fs_path, fr->fs_stderr);
                        *fr->fs_stderr = '\0';
                        ap_log_rerror(FCGI_LOG_WARN_NOERRNO, fr->r,
                            "FastCGI: too much stderr received from server \"%s\", %d bytes discarded, "
                            "increase FCGI_SERVER_MAX_STDERR_LINE_LEN (%d) and rebuild "
                            "or use \"\\n\" to terminate lines",
                            fr->fs_path, len, FCGI_SERVER_MAX_STDERR_LINE_LEN);
                        fcgi_buf_toss(fr->serverInputBuffer, len);
                    }
                }
                break;
            case FCGI_END_REQUEST:
                if (!fr->readingEndRequestBody) {
                    if (fr->dataLen != sizeof(FCGI_EndRequestBody)) {
                        ap_log_rerror(FCGI_LOG_ERR_NOERRNO, fr->r,
                            "FastCGI: comm with server \"%s\" aborted: protocol error: invalid FCGI_END_REQUEST size: "
                            "%d != sizeof(FCGI_EndRequestBody)(%d)",
                            fr->fs_path, fr->dataLen, sizeof(FCGI_EndRequestBody));
                        return SERVER_ERROR;
                    }
                    fr->readingEndRequestBody = TRUE;
                }
                if (len>0) {
                    fcgi_buf_get_to_buf(fr->erBufPtr, fr->serverInputBuffer, len);
                    fr->dataLen -= len;
                }
                if (fr->dataLen == 0) {
                    FCGI_EndRequestBody *erBody = &fr->endRequestBody;
                    fcgi_buf_get_to_block(
                        fr->erBufPtr, (char *) &fr->endRequestBody,
                        sizeof(FCGI_EndRequestBody));
                    if (erBody->protocolStatus != FCGI_REQUEST_COMPLETE) {
                        /*
                         * XXX: What to do with FCGI_OVERLOADED?
                         */
                        ap_log_rerror(FCGI_LOG_ERR_NOERRNO, fr->r,
                            "FastCGI: comm with server \"%s\" aborted: protocol error: invalid FCGI_END_REQUEST status: "
                            "%d != FCGI_REQUEST_COMPLETE(%d)", fr->fs_path,
                            erBody->protocolStatus, FCGI_REQUEST_COMPLETE);
                        return SERVER_ERROR;
                    }
                    fr->exitStatus = (erBody->appStatusB3 << 24)
                        + (erBody->appStatusB2 << 16)
                        + (erBody->appStatusB1 <<  8)
                        + (erBody->appStatusB0 );
                    fr->exitStatusSet = TRUE;
                    fr->readingEndRequestBody = FALSE;
                }
                break;
            case FCGI_GET_VALUES_RESULT:
                /* XXX coming soon */
            case FCGI_UNKNOWN_TYPE:
                /* XXX coming soon */

            /*
             * XXX Ignore unknown packet types from the FastCGI server.
             */
            default:
                fcgi_buf_toss(fr->serverInputBuffer, len);
                fr->dataLen -= len;
                break;
        } /* switch */

        /*
         * Discard padding, then start looking for
         * the next header.
         */
        if (fr->dataLen == 0) {
            if (fr->paddingLen > 0) {
                len = min(fr->paddingLen,
                        BufferLength(fr->serverInputBuffer));
                fcgi_buf_toss(fr->serverInputBuffer, len);
                fr->paddingLen -= len;
            }
            if (fr->paddingLen == 0) {
                fr->gotHeader = FALSE;
            }
        }
    } /* while */
    return OK;
}
