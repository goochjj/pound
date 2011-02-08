/*
 * Pound - the reverse-proxy load-balancer
 * Copyright (C) 2002 Apsis GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA  02111-1307, USA.
 *
 * Contact information:
 * Apsis GmbH
 * P.O.Box
 * 8707 Uetikon am See
 * Switzerland
 * Tel: +41-1-920 4904
 * EMail: roseg@apsis.ch
 */

static char *rcs_id = "$Id: http.c,v 1.8 2004/11/04 13:37:07 roseg Exp $";

/*
 * $Log: http.c,v $
 * Revision 1.8  2004/11/04 13:37:07  roseg
 * Changes:
 * - added support for non-blocking connect(2)
 * - added support for 414 - Request URI too long
 * - added RedirectRewrite directive - to prevent redirect changes
 * - added support for NoHTTPS11 value 2 (for MSIE clients only)
 * - added support for HTTPSHeaders 3 (no verify)
 *
 * Problems fixed:
 * - fixed bug if multiple listening ports/addresses
 * - fixed memory leak in SSL
 * - flush stdout (if used) after each log message
 * - assumes only 304, 305 and 306 codes to have no content
 * - fixed problem with delays in 302 without content
 * - fixed problem with time-outs in HTTPS
 *
 * Enhancements:
 * - improved threads detection code in autoconf
 * - added supervisor process disable configuration flag
 * - tweak for the Location rewriting code (only look at current GROUP)
 * - improved print-out for client certificate information
 *
 * Revision 1.7  2004/03/24 06:59:59  roseg
 * Fixed bug in X-SSL-CIPHER description
 * Changed README to stx format for consistency
 * Addedd X-SSL-certificate with full client certificate
 * Improved the response times on HTTP/0.9 (content without Content-length)
 * Improved response granularity on above - using unbuffered BIO now
 * Fixed problem with IE/SSL (SSL_set_shutdown)
 * Avoid error messages on premature EOF from client
 * Fixed HeadRemove code so all headers are checked without exception
 * Improved autoconf detection
 *
 * Revision 1.6  2003/11/30 22:56:26  roseg
 * Callback for RSA ephemeral keys:
 *     - generated in a separate thread
 *     - used if required (IE 5.0?)
 * New X-SSL-cipher header encryption level/method
 * Added CheckURL parameter in config file
 *     - perform syntax check only if value 1 (default 0)
 * Allow for empty query/param strings in URL syntax
 * Additional SSL engine loading code
 * Added parameter for CA certificates
 *     - CA list is sent to client
 * Verify client certificates up to given depth
 * Fixed vulnerability in syslog handling
 *
 * Revision 1.5  2003/10/14 08:35:45  roseg
 * Session by Basic Authentication:
 *     Session BASIC parameter added
 * Syntax checking of request.
 * User-defined request character set(s):
 *     Parameters CSsegment, CSparameter, CSqid, CSqval
 * Request size limit:
 *     Parameter MaxRequest
 * Single log function rather than #ifdefs.
 * Added LogLevel 4 (same as 3 but without the virtual host info).
 * Added HeadRemove directive (allows to delete a header from requests).
 * Location rewriting on redirect:
 *     if  the request contains a Header directive
 *         and the response is codes 301, 302, 303, 307
 *         and the Location in the response is to a known host
 *     then the Location header in the response will be rewritten to point
 *         to the Pound protocol/port itself
 *
 * Revision 1.4  2003/04/24 13:40:11  roseg
 * Added 'Server' configuration directive
 * Fixed problem with HTTPSHeaders 0 "..." - the desired header is written even if HTTPSHeaders is 0
 * Added the ability of loading a certificate chain.
 * Added compatability with OpenSSL 0.9.7
 * Added user-definable error pages.
 * Added compile-time flags to run in foreground and to log to stderr.
 * Opens separate pid files per-process.
 * Improved autoconf.
 * Some SSL speed optimisations.
 *
 * Revision 1.3  2003/02/19 13:51:59  roseg
 * Added support for OpenSSL Engine (crypto hardware)
 * Added support for Subversion WebDAV
 * Added support for mandatory client certificates
 * Added X-SSL-serial header for SSL connections
 * Fixed problem with BIO_pending in is_readable
 * Fixed problem with multi-threading in OpenSSL
 * Improved autoconf
 *
 * Revision 1.2  2003/01/20 15:15:06  roseg
 * Better handling of "100 Continue" responses
 * Fixed problem with allowed character set for requests
 *
 * Revision 1.1  2003/01/09 01:28:39  roseg
 * Better auto-conf detection
 * LogLevel 3 for Apache-like log (Combined Log Format)
 * Don't ask client for certificate if no SSL headers required
 * Added handling for 'Connection: closed' header
 * Added monitor process to restart worker process if crashed
 * Added possibility to listen on all interfaces
 * Fixed HeadDeny code
 * Fixed problem with threads on *BSD
 *
 * Revision 1.0  2002/10/31 15:21:24  roseg
 * fixed ordering of certificate file
 * removed thread auto clean-up (bug in Linux implementation of libpthread)
 * added support for additional WebDAV commands (Microsoft)
 * restructured request match patterns
 * added support for HA ports for back-end hosts
 * added support for optional HTTPS extra header
 *
 * Revision 0.11  2002/09/18 15:07:25  roseg
 * session tracking via IP, URL param, cookie
 * open sockets with REUSEADDR; check first noone else uses them
 * fixed bug in responses without content but Content-length (1xx, 204, 304)
 * added early pruning of sessions to "dead" back-end hosts
 *
 * Revision 0.10  2002/09/05 15:31:31  roseg
 * Added required/disallowed headers matching in groups
 * Configurable cyphers/strength for SSL
 * Fixed bug in multiple requests per connection (GROUP matching)
 * Fixed missing '~' in URL matching
 * Retry request on discovering dead back-end
 * Fixed bug in reading certificate/private-key file
 * Added configure script
 * Configurable logging facility
 *
 * Revision 0.9  2002/08/19 08:19:53  roseg
 * Added support for listening on multiple addresses/ports
 * Added support/configuration for WebDAV (LOCK/UNLOCK)
 * Added support for old-style HTTP/1.0 responses (content to EOF)
 * Fixed threads stack size problem on *BSD (#ifdef NEED_STACK)
 * Fixed problem in URL extraction
 *
 * Revision 0.8  2002/08/01 13:29:15  roseg
 * fixed bug in server timeout/close detection
 * fixed problem with SSL multi-threading
 * header collection
 * extended request patterns as per RFC
 * fixed problem with HEAD response (ignore content length)
 *
 * Revision 0.7  2002/07/23 03:11:27  roseg
 * Moved entirely to BIO (rather then the old comm_)
 * Added HTTPS-specific headers
 * Fixed a few minor problems in the pattern matching
 *
 * Revision 0.6  2002/07/16 21:14:01  roseg
 * added URL groups and matching
 * extended URL reuest matching
 * moved to "modern" regex
 *
 * Revision 0.5  2002/07/04 12:23:31  roseg
 * code split
 *
 */

#include    "pound.h"

/* HTTP error replies */
static char *h500 = "500 Internal Server Error",
            *h501 = "501 Not Implemented",
            *h503 = "503 Service Unavailable",
            *h414 = "414 Request URI too long";

static char *err_head = "HTTP/1.0 %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s";
static char *err_cont = "<html><head><title>%s</title></head><body><h1>%s</h1><p>%s</p></body></html>";

/*
 * Reply with an error
 */
static void
err_reply(BIO *c, char *head, char *txt)
{
    char    rep[MAXBUF], cont[MAXBUF];

    snprintf(cont, sizeof(cont), err_cont, head, head, txt);
    snprintf(rep, sizeof(rep), err_head, head, strlen(cont), cont);
    BIO_write(c, rep, strlen(rep));
    return;
}

/*
 * Read and write some binary data
 */
static int
copy_bin(BIO *cl, BIO *be, long cont, long *res_bytes, int no_write)
{
    char        buf[MAXBUF];
    int         res;

    while(cont > 0L) {
        if((res = BIO_read(cl, buf, cont > MAXBUF? MAXBUF: cont)) < 0)
            return -1;
        else if(res == 0)
            return -2;
        if(!no_write)
            if(BIO_write(be, buf, res) != res)
                return -3;
        if(BIO_flush(be) != 1)
            return -4;
        cont -= res;
        if(res_bytes)
            *res_bytes += res;
    }
    return 0;
}

/*
 * Strip trailing CRLF
 */
static void
strip_eol(char *lin)
{
    while(*lin)
        if(*lin == '\n' || (*lin == '\r' && *(lin + 1) == '\n')) {
            *lin = '\0';
            break;
        } else
            lin++;
    return;
}

/*
 * Copy chunked
 */
static int
copy_chunks(BIO *cl, BIO *be, long *res_bytes, int no_write, long max_size)
{
    char        buf[MAXBUF];
    long        cont, tot_size;
    regmatch_t  matches[2];

    for(tot_size = 0L;;) {
        if(BIO_gets(cl, buf, MAXBUF) <= 0) {
            if(errno)
                logmsg(LOG_WARNING, "unexpected chunked EOF: %s", strerror(errno));
            return -1;
        }
        strip_eol(buf);
        if(!regexec(&CHUNK_HEAD, buf, 2, matches, 0))
            cont = strtol(buf, NULL, 16);
        else {
            /* not chunk header */
            logmsg(LOG_WARNING, "bad chunk header <%s>: %s", buf, strerror(errno));
            return -2;
        }
        if(!no_write)
            if(BIO_printf(be, "%s\r\n", buf) <= 0) {
                logmsg(LOG_WARNING, "error write chunked: %s", strerror(errno));
                return -3;
            }

        tot_size += cont;
        if(max_size > 0L && tot_size > max_size) {
            logmsg(LOG_WARNING, "chunk content too large");
                return -4;
        }

        if(cont > 0L) {
            if(copy_bin(cl, be, cont, res_bytes, no_write)) {
                if(errno)
                    logmsg(LOG_WARNING, "error copy chunk cont: %s", strerror(errno));
                return -4;
            }
        } else
            break;
        /* final CRLF */
        if(BIO_gets(cl, buf, MAXBUF) <= 0) {
            if(errno)
                logmsg(LOG_WARNING, "unexpected after chunk EOF: %s", strerror(errno));
            return -5;
        }
        strip_eol(buf);
        if(buf[0])
            logmsg(LOG_WARNING, "unexpected after chunk \"%s\"", buf);
        if(!no_write)
            if(BIO_printf(be, "%s\r\n", buf) <= 0) {
                logmsg(LOG_WARNING, "error after chunk write: %s", strerror(errno));
                return -6;
            }
    }
    /* possibly trailing headers */
    for(;;) {
        if(BIO_gets(cl, buf, MAXBUF) <= 0) {
            if(errno)
                logmsg(LOG_WARNING, "unexpected post-chunk EOF: %s", strerror(errno));
            return -7;
        }
        if(!no_write) {
            if(BIO_puts(be, buf) <= 0) {
                logmsg(LOG_WARNING, "error post-chunk write: %s", strerror(errno));
                return -8;
            }
            if(BIO_flush(be) != 1) {
                logmsg(LOG_WARNING, "copy_chunks flush error: %s", strerror(errno));
                return -4;
            }
        }
        strip_eol(buf);
        if(!buf[0])
            break;
    }
    return 0;
}

static int  err_to = -1;

/*
 * Time-out for client read/gets
 * the SSL manual says not to do it, but it works well enough anyway...
 */
static long
bio_callback(BIO *bio, int cmd, const char *argp, int argi, long argl, long ret)
{
    struct pollfd   p;
    int             to;

    if(cmd != BIO_CB_READ && cmd != BIO_CB_WRITE)
        return ret;

    /* a time-out already occured */
    if((to = *((int *)BIO_get_callback_arg(bio)) * 1000) < 0) {
        errno = ETIMEDOUT;
        return -1;
    }

    for(;;) {
        memset(&p, 0, sizeof(p));
        BIO_get_fd(bio, &p.fd);
        p.events = (cmd == BIO_CB_READ)? (POLLIN | POLLPRI): POLLOUT;
        switch(poll(&p, 1, to)) {
        case 1:
            if(cmd == BIO_CB_READ) {
                if(p.revents == POLLIN || p.revents == POLLPRI)
                    /* there is readable data */
                    return ret;
                else
                    errno = EIO;
            } else {
                if(p.revents == POLLOUT)
                    /* data can be written */
                    return ret;
                else
                    errno = ECONNRESET;
            }
            return -1;
        case 0:
            /* timeout - mark the BIO as unusable for the future */
            BIO_set_callback_arg(bio, (char *)&err_to);
            errno = ETIMEDOUT;
            return 0;
        default:
            /* error */
            if(errno != EINTR) {
                logmsg(LOG_WARNING, "callback poll: %s", strerror(errno));
                return -2;
            }
        }
    }
}

/*
 * Check if the file underlying a BIO is readable
 */
static int
is_readable(BIO *bio, int to_wait)
{
    struct pollfd   p;

    if(BIO_pending(bio) > 0)
        return 1;
    memset(&p, 0, sizeof(p));
    BIO_get_fd(bio, &p.fd);
    p.events = POLLIN | POLLPRI;
    return (poll(&p, 1, to_wait * 1000) > 0);
}

static void
free_headers(char **headers)
{
    int     i;

    for(i = 0; i < MAXHEADERS; i++)
        if(headers[i])
            free(headers[i]);
    free(headers);
    return;
}

static char **
get_headers(BIO *in, BIO *cl)
{
    char    **headers, buf[MAXBUF];
    int     res, n;

    /* HTTP/1.1 allows leading CRLF */
    while((res = BIO_gets(in, buf, MAXBUF)) > 0) {
        strip_eol(buf);
        if(buf[0])
            break;
    }

    if(res <= 0) {
        /* this is expected to occur only on client reads */
        /* logmsg(LOG_WARNING, "headers: bad starting read"); */
        return NULL;
    } else if(res >= (MAXBUF - 1)) {
        /* check for request length limit */
        logmsg(LOG_WARNING, "headers: request URI too long");
        err_reply(cl, h414, e414);
        return NULL;
    }

    if((headers = (char **)calloc(MAXHEADERS, sizeof(char *))) == NULL) {
        logmsg(LOG_WARNING, "headers: out of memory");
        err_reply(cl, h500, e500);
        return NULL;
    }

    for(n = 0; n < MAXHEADERS; n++) {
        if((headers[n] = (char *)malloc(MAXBUF)) == NULL) {
            free_headers(headers);
            logmsg(LOG_WARNING, "header: out of memory");
            err_reply(cl, h500, e500);
            return NULL;
        }
        strncpy(headers[n], buf, MAXBUF - 1);
        if((res = BIO_gets(in, buf, MAXBUF)) <= 0) {
            free_headers(headers);
            logmsg(LOG_WARNING, "can't read header");
            err_reply(cl, h500, e500);
            return NULL;
        }
        strip_eol(buf);
        if(!buf[0])
            return headers;
    }

    free_headers(headers);
    logmsg(LOG_WARNING, "too many headers");
    err_reply(cl, h500, e500);
    return NULL;
}

/*
 * Apache log-file-style time format
 */
static char *
log_time(time_t when)
{
    static char res[32];

    strftime(res, sizeof(res), "%d/%b/%Y:%H:%M:%S %z", localtime(&when));
    return res;
}

/*
 * Apache log-file-style number format
 */
static char *
log_bytes(long cnt)
{
    static char res[16];

    if(cnt > 0L)
        snprintf(res, sizeof(res), "%ld", cnt);
    else
        strcpy(res, "-");
    return res;
}

/*
 * Check the validity of a URL
 */
static int
URL_syntax(char *line)
{
    int len, span;

    if(!check_URL)
        return 0;
    for(len = 0; line[len] == '/'; ) {
        len++;
        if(!(span = strspn(line + len, CS_segment))) {
            if(line[len] == '?' || line[len] == '#')
                break;
        } else
            len += span;
        if(line[len] == ';') {
            len++;
            if(!(span = strspn(line + len, CS_parm)))
                return -1;
            len += span;
        }
    }
    if(line[len] == '?') {
        len++;
        for(;;) {
            if(!(span = strspn(line + len, CS_qid))) {
                if(line[len] == '#' || line[len] == '\0')
                    break;
                if(line[len] == '&') {
                    len++;
                    continue;
                }
                return -2;
            }
            len += span;
            if(line[len] == '=') {
                len++;
                len += strspn(line + len, CS_qval);
            }
            if(line[len] == '&')
                len++;
            else
                break;
        }
    }
    if(line[len] == '#') {
        len++;
        len += strspn(line + len, CS_frag);
    }
    return line[len];
}

/* Cleanup code. This should really be in the pthread_cleanup_push, except for bugs in some implementations */
#define clean_all() {   \
    if(ssl != NULL) { BIO_ssl_shutdown(cl); BIO_ssl_shutdown(cl); BIO_ssl_shutdown(cl); } \
    if(be != NULL) { BIO_flush(be); BIO_reset(be); BIO_free_all(be); be = NULL; } \
    if(cl != NULL) { BIO_flush(cl); BIO_reset(cl); BIO_free_all(cl); cl = NULL; } \
    if(x509 != NULL) { X509_free(x509); x509 = NULL; } \
    if(ssl != NULL) { ERR_clear_error(); ERR_remove_state(0); } \
}

/*
 * handle an HTTP request
 */
void *
thr_http(void *arg)
{
    BIO                 *cl, *be, *bb;
    X509                *x509;
    SSL                 *ssl;
    thr_arg             *a;
    struct in_addr      from_host;
    struct sockaddr_in  *srv, to_host;
    int                 cl_11, be_11, res, chunked, n, sock, no_cont, skip, conn_closed, redir,
                        force_10;
    char                request[MAXBUF], response[MAXBUF], buf[MAXBUF], url[MAXBUF], loc_path[MAXBUF], **headers,
                        headers_ok[MAXHEADERS], v_host[MAXBUF], referer[MAXBUF], u_agent[MAXBUF], *mh;
    long                cont, res_bytes;
    time_t              req_start;
    regmatch_t          matches[4];
    struct linger       l;
    GROUP               *grp;

    a = (thr_arg *)arg;
    from_host = a->from_host;
    to_host = a->to_host;
    sock = a->sock;
    ssl = a->ssl;
    free(a);

    n = 1;
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&n, sizeof(n));
    l.l_onoff = 1;
    l.l_linger = 10;
    setsockopt(sock, SOL_SOCKET, SO_LINGER, (void *)&l, sizeof(l));

    cl = NULL;
    be = NULL;
    x509 = NULL;

    if((cl = BIO_new_socket(sock, 1)) == NULL) {
        logmsg(LOG_WARNING, "BIO_new_socket failed");
        shutdown(sock, 2);
        close(sock);
        pthread_exit(NULL);
    }
    if(clnt_to > 0) {
        BIO_set_callback_arg(cl, (char *)&clnt_to);
        BIO_set_callback(cl, bio_callback);
    }

    if(ssl != NULL) {
        SSL_set_bio(ssl, cl, cl);
        if((bb = BIO_new(BIO_f_ssl())) == NULL) {
            logmsg(LOG_WARNING, "BIO_new(Bio_f_ssl()) failed");
            BIO_reset(cl);
            BIO_free_all(cl);
            pthread_exit(NULL);
        }
        BIO_set_ssl(bb, ssl, BIO_CLOSE);
        BIO_set_ssl_mode(bb, 0);
        cl = bb;
        if(BIO_do_handshake(cl) <= 0) {
            /* no need to log every client without a certificate...
            logmsg(LOG_WARNING, "BIO_do_handshake with %s failed: %s", inet_ntoa(from_host),
                ERR_error_string(ERR_get_error(), NULL));
            x509 = NULL;
            */
            BIO_reset(cl);
            BIO_free_all(cl);
            pthread_exit(NULL);
        } else {
            if((x509 = SSL_get_peer_certificate(ssl)) != NULL && https_headers < 3 && SSL_get_verify_result(ssl) != X509_V_OK) {
                logmsg(LOG_WARNING, "Bad certificate from %s", inet_ntoa(from_host));
                BIO_reset(cl);
                BIO_free_all(cl);
                pthread_exit(NULL);
            }
        }
        /*
         * This is dealt with in the handshake
        if(https_headers == 2 && x509 == NULL) {
            BIO_reset(cl);
            BIO_free_all(cl);
            pthread_exit(NULL);
        }
        */
    } else {
        x509 = NULL;
    }

    if((bb = BIO_new(BIO_f_buffer())) == NULL) {
        logmsg(LOG_WARNING, "BIO_new(buffer) failed");
        BIO_reset(cl);
        BIO_free_all(cl);
        pthread_exit(NULL);
    }
    BIO_set_close(cl, BIO_CLOSE);
    BIO_set_buffer_size(cl, MAXBUF);
    cl = BIO_push(bb, cl);

    for(cl_11 = be_11 = 0;;) {
        req_start = time(NULL);
        res_bytes = 0L;
        v_host[0] = referer[0] = u_agent[0] = '\0';
        conn_closed = 0;
        for(n = 0; n < MAXHEADERS; n++)
            headers_ok[n] = 1;
        if((headers = get_headers(cl, cl)) == NULL) {
            if(!cl_11) {
                if(errno)
                    logmsg(LOG_WARNING, "error read from %s: %s", inet_ntoa(from_host), strerror(errno));
                /* err_reply(cl, h500, e500); */
            }
            clean_all();
            pthread_exit(NULL);
        }

        /* check for correct request */
        strncpy(request, headers[0], MAXBUF);
        if(!regexec(&HTTP, request, 3, matches, 0)) {
            no_cont = !strncasecmp(request + matches[1].rm_so, "HEAD", matches[1].rm_eo - matches[1].rm_so);
        } else if(allow_xtd && !regexec(&XHTTP, request, 3, matches, 0)) {
            no_cont = !strncasecmp(request + matches[1].rm_so, "DELETE", matches[1].rm_eo - matches[1].rm_so);
        } else if(allow_dav && !regexec(&WEBDAV, request, 3, matches, 0)) {
            /* Other WebDAV requests may also result in no content, but we don't know - Microsoft won't tell us */
            no_cont = !(strncasecmp(request + matches[1].rm_so, "LOCK", matches[1].rm_eo - matches[1].rm_so)
                    || strncasecmp(request + matches[1].rm_so, "UNLOCK", matches[1].rm_eo - matches[1].rm_so)
                    || strncasecmp(request + matches[1].rm_so, "DELETE", matches[1].rm_eo - matches[1].rm_so)
                    || strncasecmp(request + matches[1].rm_so, "OPTIONS", matches[1].rm_eo - matches[1].rm_so));
        } else {
            logmsg(LOG_WARNING, "bad request \"%s\" from %s", request, inet_ntoa(from_host));
            err_reply(cl, h501, e501);
            free_headers(headers);
            clean_all();
            pthread_exit(NULL);
        }
        cl_11 = (request[strlen(request) - 1] == '1');
        strncpy(url, request + matches[2].rm_so, matches[2].rm_eo - matches[2].rm_so);
        url[matches[2].rm_eo - matches[2].rm_so] = '\0';
        if(URL_syntax(url)) {
            logmsg(LOG_WARNING, "bad URL \"%s\" from %s", url, inet_ntoa(from_host));
            err_reply(cl, h501, e501);
            free_headers(headers);
            clean_all();
            pthread_exit(NULL);
        }

        /* check other headers */
        for(chunked = 0, cont = 0L, n = 1; n < MAXHEADERS && headers[n]; n++) {
            /* no overflow - see check_header for details */
            switch(check_header(headers[n], buf)) {
            case HEADER_HOST:
                strcpy(v_host, buf);
                if((mh = add_port(buf, &to_host)) != NULL) {
                    free(headers[n]);
                    headers[n] = mh;
                }
                break;
            case HEADER_REFERER:
                strcpy(referer, buf);
                break;
            case HEADER_USER_AGENT:
                strcpy(u_agent, buf);
                break;
            case HEADER_CONNECTION:
                if(!strcasecmp("close", buf))
                    conn_closed = 1;
                break;
            case HEADER_TRANSFER_ENCODING:
                if(!strcasecmp("chunked", buf))
                    chunked = 1;
                break;
            case HEADER_CONTENT_LENGTH:
                cont = atol(buf);
                break;
            case HEADER_ILLEGAL:
                if(log_level > 0)
                    logmsg(LOG_WARNING, "bad header from %s (%s)", inet_ntoa(from_host), headers[n]);
                headers_ok[n] = 0;
                break;
            }
            if(headers_ok[n] && head_off) {
                /* maybe header to be removed */
                int i;

                for(i = 0; i < n_head_off; i++)
                    headers_ok[n] = regexec(&head_off[i], headers[n], 0, NULL, 0);
            }
        }

        /* possibly limited request size */
        if(max_req > 0L && cont > 0L && cont > max_req) {
            logmsg(LOG_WARNING, "request too large (%ld) from %s", cont, inet_ntoa(from_host));
            err_reply(cl, h501, e501);
            free_headers(headers);
            clean_all();
            pthread_exit(NULL);
        }

        if(be != NULL) {
            if(is_readable(be, 0)) {
                /* The only way it's readable is if it's at EOF, so close it! */
                BIO_reset(be);
                BIO_free_all(be);
                be = NULL;
            }
        }
        /* check that the requested URL still fits the old back-end */
        if(be != NULL && grp != get_grp(url, &headers[1])) {
            BIO_reset(be);
            BIO_free_all(be);
            be = NULL;
        }
        while(be == NULL) {
            /* find the session - if any */
            if((srv = get_be(grp = get_grp(url, &headers[1]), from_host, url, &headers[1])) == NULL) {
				logmsg(LOG_WARNING, "no backend \"%s\" from %s", request, inet_ntoa(from_host));
                err_reply(cl, h503, e503);
                free_headers(headers);
                clean_all();
                pthread_exit(NULL);
            }

            if((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
                logmsg(LOG_WARNING, "backend %s:%hd create: %s",
                    inet_ntoa(srv->sin_addr), ntohs(srv->sin_port), strerror(errno));
                err_reply(cl, h503, e503);
                free_headers(headers);
                clean_all();
                pthread_exit(NULL);
            }
            if(connect_nb(sock, (struct sockaddr *)srv, (socklen_t)sizeof(*srv)) < 0) {
                logmsg(LOG_WARNING, "backend %s:%hd connect: %s",
                    inet_ntoa(srv->sin_addr), ntohs(srv->sin_port), strerror(errno));
                close(sock);
                kill_be(srv);
                continue;
            }
            n = 1;
            setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&n, sizeof(n));
            l.l_onoff = 1;
            l.l_linger = 10;
            setsockopt(sock, SOL_SOCKET, SO_LINGER, (void *)&l, sizeof(l));
            if((be = BIO_new_socket(sock, 1)) == NULL) {
                logmsg(LOG_WARNING, "BIO_new_socket server failed");
                shutdown(sock, 2);
                close(sock);
                free_headers(headers);
                clean_all();
                pthread_exit(NULL);
            }
            BIO_set_close(be, BIO_CLOSE);
            if(server_to > 0) {
                BIO_set_callback_arg(be, (char *)&server_to);
                BIO_set_callback(be, bio_callback);
            }
            if((bb = BIO_new(BIO_f_buffer())) == NULL) {
                logmsg(LOG_WARNING, "BIO_new(buffer) server failed");
                free_headers(headers);
                clean_all();
                pthread_exit(NULL);
            }
            BIO_set_buffer_size(bb, MAXBUF);
            BIO_set_close(bb, BIO_CLOSE);
            be = BIO_push(bb, be);
        }

        /* send the request */
        for(n = 0; n < MAXHEADERS && headers[n]; n++) {
            if(!headers_ok[n])
                continue;
            if(BIO_printf(be, "%s\r\n", headers[n]) <= 0) {
                logmsg(LOG_WARNING, "error write to %s:%hd: %s",
                    inet_ntoa(srv->sin_addr), ntohs(srv->sin_port), strerror(errno));
                err_reply(cl, h500, e500);
                free_headers(headers);
                clean_all();
                pthread_exit(NULL);
            }
        }
        free_headers(headers);

        /* if SSL put additional headers for client certificate */
        if(ssl != NULL) {
            SSL_CIPHER  *cipher;

            if(https_header != NULL)
                if(BIO_printf(be, "%s\r\n", https_header) <= 0) {
                    logmsg(LOG_WARNING, "error write HTTPSHeader to %s:%hd: %s",
                        inet_ntoa(srv->sin_addr), ntohs(srv->sin_port), strerror(errno));
                    err_reply(cl, h500, e500);
                    clean_all();
                    pthread_exit(NULL);
                }
            if(https_headers > 0 && x509 != NULL && (bb = BIO_new(BIO_s_mem())) != NULL) {
                X509_NAME_print_ex(bb, X509_get_subject_name(x509), 8, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
                BIO_gets(bb, buf, MAXBUF);
                if(BIO_printf(be, "X-SSL-Subject: %s\r\n", buf) <= 0) {
                    logmsg(LOG_WARNING, "error write X-SSL-Subject to %s:%hd: %s",
                        inet_ntoa(srv->sin_addr), ntohs(srv->sin_port), strerror(errno));
                    err_reply(cl, h500, e500);
                    BIO_free_all(bb);
                    clean_all();
                    pthread_exit(NULL);
                }

                X509_NAME_print_ex(bb, X509_get_issuer_name(x509), 8, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
                BIO_gets(bb, buf, MAXBUF);
                if(BIO_printf(be, "X-SSL-Issuer: %s\r\n", buf) <= 0) {
                    logmsg(LOG_WARNING, "error write X-SSL-Issuer to %s:%hd: %s",
                        inet_ntoa(srv->sin_addr), ntohs(srv->sin_port), strerror(errno));
                    err_reply(cl, h500, e500);
                    BIO_free_all(bb);
                    clean_all();
                    pthread_exit(NULL);
                }

                ASN1_TIME_print(bb, X509_get_notBefore(x509));
                BIO_gets(bb, buf, MAXBUF);
                if(BIO_printf(be, "X-SSL-notBefore: %s\r\n", buf) <= 0) {
                    logmsg(LOG_WARNING, "error write X-SSL-notBefore to %s:%hd: %s",
                        inet_ntoa(srv->sin_addr), ntohs(srv->sin_port), strerror(errno));
                    err_reply(cl, h500, e500);
                    BIO_free_all(bb);
                    clean_all();
                    pthread_exit(NULL);
                }

                ASN1_TIME_print(bb, X509_get_notAfter(x509));
                BIO_gets(bb, buf, MAXBUF);
                if(BIO_printf(be, "X-SSL-notAfter: %s\r\n", buf) <= 0) {
                    logmsg(LOG_WARNING, "error write X-SSL-notAfter to %s:%hd: %s",
                        inet_ntoa(srv->sin_addr), ntohs(srv->sin_port), strerror(errno));
                    err_reply(cl, h500, e500);
                    BIO_free_all(bb);
                    clean_all();
                    pthread_exit(NULL);
                }
                if(BIO_printf(be, "X-SSL-serial: %ld\r\n", ASN1_INTEGER_get(X509_get_serialNumber(x509))) <= 0) {
                    logmsg(LOG_WARNING, "error write X-SSL-serial to %s:%hd: %s",
                        inet_ntoa(srv->sin_addr), ntohs(srv->sin_port), strerror(errno));
                    err_reply(cl, h500, e500);
                    BIO_free_all(bb);
                    clean_all();
                    pthread_exit(NULL);
                }
                PEM_write_bio_X509(bb, x509);
                BIO_gets(bb, buf, MAXBUF);
                strip_eol(buf);
                if(BIO_printf(be, "X-SSL-certificate: %s\r\n", buf) <= 0) {
                    logmsg(LOG_WARNING, "error write X-SSL-certificate to %s:%hd: %s",
                        inet_ntoa(srv->sin_addr), ntohs(srv->sin_port), strerror(errno));
                    err_reply(cl, h500, e500);
                    BIO_free_all(bb);
                    clean_all();
                    pthread_exit(NULL);
                }
                while(BIO_gets(bb, buf, MAXBUF) > 0) {
                    strip_eol(buf);
                    if(BIO_printf(be, "\t%s\r\n", buf) <= 0) {
                        logmsg(LOG_WARNING, "error write X-SSL-certificate to %s:%hd: %s",
                            inet_ntoa(srv->sin_addr), ntohs(srv->sin_port), strerror(errno));
                        err_reply(cl, h500, e500);
                        BIO_free_all(bb);
                        clean_all();
                        pthread_exit(NULL);
                    }
                }
                BIO_free_all(bb);
            }
            if((cipher = SSL_get_current_cipher(ssl)) != NULL) {
                SSL_CIPHER_description(cipher, buf, MAXBUF);
                strip_eol(buf);
                if(BIO_printf(be, "X-SSL-cipher: %s\r\n", buf) <= 0) {
                    logmsg(LOG_WARNING, "error write X-SSL-cipher to %s:%hd: %s",
                        inet_ntoa(srv->sin_addr), ntohs(srv->sin_port), strerror(errno));
                    err_reply(cl, h500, e500);
                    clean_all();
                    pthread_exit(NULL);
                }
            }
        }
        /* put additional client IP header */
        BIO_printf(be, "X-Forwarded-For: %s\r\n", inet_ntoa(from_host));

        /* final CRLF */
        BIO_puts(be, "\r\n");

        if(cl_11 && chunked) {
            /* had Transfer-encoding: chunked so read/write all the chunks (HTTP/1.1 only) */
            if(copy_chunks(cl, be, NULL, 0, max_req)) {
                err_reply(cl, h500, e500);
                clean_all();
                pthread_exit(NULL);
            }
        } else if(cont > 0L) {
            /* had Content-length, so do raw reads/writes for the length */
            if(copy_bin(cl, be, cont, NULL, 0)) {
                logmsg(LOG_WARNING, "error copy client cont: %s", strerror(errno));
                err_reply(cl, h500, e500);
                clean_all();
                pthread_exit(NULL);
            }
        }

        /* flush to the back-end */
        if(BIO_flush(be) != 1) {
            logmsg(LOG_WARNING, "error flush to %s:%hd: %s",
                inet_ntoa(srv->sin_addr), ntohs(srv->sin_port), strerror(errno));
            err_reply(cl, h500, e500);
            clean_all();
            pthread_exit(NULL);
        }

        /*
         * check on no_https_11:
         *  - if 0 ignore
         *  - if 1 and SSL force HTTP/1.0
         *  - if 2 and SSL and MSIE force HTTP/1.0
         */
        switch(no_https_11) {
        case 1:
            force_10 = (ssl != NULL);
            break;
        case 2:
            force_10 = (ssl != NULL && strstr(u_agent, "MSIE") != NULL);
            break;
        default:
            force_10 = 0;
            break;
        }

        /* get the response */
        for(skip = 1; skip;) {
            if((headers = get_headers(be, cl)) == NULL) {
                logmsg(LOG_WARNING, "response error read from %s:%hd: %s",
                    inet_ntoa(srv->sin_addr), ntohs(srv->sin_port), strerror(errno));
                err_reply(cl, h500, e500);
                clean_all();
                pthread_exit(NULL);
            }

            strncpy(response, headers[0], MAXBUF);
            be_11 = (response[7] == '1');
            /* responses with code 100 are never passed back to the client */
            skip = !regexec(&RESP_SKIP, response, 0, NULL, 0);
            /* some response codes (1xx, 204, 304) have no content */
            if(!no_cont && !regexec(&RESP_IGN, response, 0, NULL, 0))
                no_cont = 1;
            /* check for redirection */
            redir = !regexec(&RESP_REDIR, response, 0, NULL, 0);

            for(chunked = 0, cont = -1L, n = 1; n < MAXHEADERS && headers[n]; n++) {
                switch(check_header(headers[n], buf)) {
                case HEADER_CONNECTION:
                    if(!strcasecmp("close", buf))
                        conn_closed = 1;
                    break;
                case HEADER_TRANSFER_ENCODING:
                    if(!strcasecmp("chunked", buf)) {
                        chunked = 1;
                        no_cont = 0;
                    }
                    break;
                case HEADER_CONTENT_LENGTH:
                    cont = atol(buf);
                    break;
                case HEADER_LOCATION:
                    if(rewrite_redir && redir && v_host[0] && is_be(buf, &to_host, loc_path, grp)) {
                        snprintf(buf, MAXBUF, "Location: %s://%s/%s",
                            (ssl == NULL? "http": "https"), v_host, loc_path);
                        free(headers[n]);
                        if((headers[n] = strdup(buf)) == NULL) {
                            logmsg(LOG_WARNING, "rewrite Location - out of memory: %s", strerror(errno));
                            free_headers(headers);
                            clean_all();
                            pthread_exit(NULL);
                        }
                    }
                    break;
                }
            }

            /* possibly record session information (only for cookies) */
            upd_session(grp, &headers[1], srv);

            /* send the response */
            if(!skip)
                for(n = 0; n < MAXHEADERS && headers[n]; n++) {
                    if(BIO_printf(cl, "%s\r\n", headers[n]) <= 0) {
                        if(errno)
                            logmsg(LOG_WARNING, "error write to %s: %s", inet_ntoa(from_host), strerror(errno));
                        free_headers(headers);
                        clean_all();
                        pthread_exit(NULL);
                    }
                }
            free_headers(headers);

            /* final CRLF */
            if(!skip)
                BIO_puts(cl, "\r\n");
            if(BIO_flush(cl) != 1) {
                if(errno)
                    logmsg(LOG_WARNING, "error flush headers to %s: %s", inet_ntoa(from_host), strerror(errno));
                clean_all();
                pthread_exit(NULL);
            }

            if(!no_cont) {
                /* ignore this if request was HEAD or similar */
                if(be_11 && chunked) {
                    /* had Transfer-encoding: chunked so read/write all the chunks (HTTP/1.1 only) */
                    if(copy_chunks(be, cl, &res_bytes, skip, 0L)) {
                        /* copy_chunks() has its own error messages */
                        clean_all();
                        pthread_exit(NULL);
                    }
                } else if(cont >= 0L) {
                    /* may have had Content-length, so do raw reads/writes for the length */
                    if(copy_bin(be, cl, cont, &res_bytes, skip)) {
                        if(errno)
                            logmsg(LOG_WARNING, "error copy server cont: %s", strerror(errno));
                        clean_all();
                        pthread_exit(NULL);
                    }
                } else if(!skip) {
                    if(is_readable(be, SERVER_TO)) {
                        char    one;
                        BIO     *be_unbuf;
                        /*
                         * old-style response - content until EOF
                         * also implies the client may not use HTTP/1.1
                         */
                        cl_11 = be_11 = 0;

                        /*
                         * first read whatever is already in the input buffer
                         */
                        while(BIO_pending(be)) {
                            if(BIO_read(be, &one, 1) != 1) {
                                logmsg(LOG_WARNING, "error read response pending: %s", strerror(errno));
                                clean_all();
                                pthread_exit(NULL);
                            }
                            if(BIO_write(cl, &one, 1) != 1) {
                                if(errno)
                                    logmsg(LOG_WARNING, "error write response pending: %s", strerror(errno));
                                clean_all();
                                pthread_exit(NULL);
                            }
                            res_bytes++;
                        }
                        BIO_flush(cl);

                        /*
                         * find the socket BIO in the chain
                         */
                        if((be_unbuf = BIO_find_type(be, BIO_TYPE_SOCKET)) == NULL) {
                            logmsg(LOG_WARNING, "error get unbuffered: %s", strerror(errno));
                            clean_all();
                            pthread_exit(NULL);
                        }

                        /*
                         * copy till EOF
                         */
                        while((res = BIO_read(be_unbuf, buf, MAXBUF)) > 0) {
                            if(BIO_write(cl, buf, res) != res) {
                                if(errno)
                                    logmsg(LOG_WARNING, "error copy response body: %s", strerror(errno));
                                clean_all();
                                pthread_exit(NULL);
                            } else {
                                res_bytes += res;
                                BIO_flush(cl);
                            }
                        }
                    }
                }
                if(BIO_flush(cl) != 1) {
                    if(errno)
                        logmsg(LOG_WARNING, "error final flush to %s: %s", inet_ntoa(from_host), strerror(errno));
                    clean_all();
                    pthread_exit(NULL);
                }
            }
        }

        /* log what happened */
        strip_eol(request);
        strip_eol(response);
        switch(log_level) {
        case 0:
            break;
        case 1:
            logmsg(LOG_INFO, "%s %s - %s", inet_ntoa(from_host), request, response);
            break;
        case 2:
            snprintf(buf, sizeof(buf), "%s:%hd", inet_ntoa(srv->sin_addr), ntohs(srv->sin_port));
            logmsg(LOG_INFO, "%s %s - %s (%s)", inet_ntoa(from_host), request, response, buf);
            break;
        case 3:
            if(v_host[0])
                logmsg(LOG_INFO, "%s %s - - [%s] \"%s\" %c%c%c %s \"%s\" \"%s\"", v_host, inet_ntoa(from_host),
                    log_time(req_start), request, response[9], response[10], response[11], log_bytes(res_bytes),
                    referer, u_agent);
            else
                logmsg(LOG_INFO, "%s - - [%s] \"%s\" %c%c%c %s \"%s\" \"%s\"", inet_ntoa(from_host),
                    log_time(req_start), request, response[9], response[10], response[11], log_bytes(res_bytes),
                    referer, u_agent);
            break;
        case 4:
            logmsg(LOG_INFO, "%s - - [%s] \"%s\" %c%c%c %s \"%s\" \"%s\"", inet_ntoa(from_host),
                log_time(req_start), request, response[9], response[10], response[11], log_bytes(res_bytes),
                referer, u_agent);
            break;
        }

        if(!be_11) {
            BIO_reset(be);
            BIO_free_all(be);
            be = NULL;
        }
        /*
         * Stop processing if:
         *  - client is not HTTP/1.1
         *      or
         *  - we had a "Connection: closed" header
         *      or
         *  - this is an SSL connection and we had a NoHTTPS11 directive
         */
        if(!cl_11 || conn_closed || force_10)
            break;
    }

    /*
     * This may help with some versions of IE with a broken channel shutdown
     */
    if(ssl != NULL)
        SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);

    clean_all();
    pthread_exit(NULL);
}
