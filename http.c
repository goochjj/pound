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

static char *rcs_id = "$Id: http.c,v 1.1 2003/01/09 01:28:39 roseg Rel roseg $";

/*
 * $Log: http.c,v $
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

/* HTTP error replies and formats */
static char *h500 = "500 Internal Server Error",
            *e500 = "An internal server error occurred. Please try again later.",
            *h501 = "501 Not Implemented",
            *e501 = "This method may not be used.",
            *h503 = "503 Service Unavailable",
            *e503 = "The service is not available. Please try again later.";

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
copy_bin(BIO *cl, BIO *be, long cont, long *res_bytes)
{
    char        buf[MAXBUF];
    int         res;

    while(cont > 0L) {
        if((res = BIO_read(cl, buf, cont > MAXBUF? MAXBUF: cont)) < 0)
            return -1;
        if(res == 0)
            return 0;
        if(BIO_write(be, buf, res) != res)
            return -2;
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
copy_chunks(BIO *cl, BIO *be, long *res_bytes)
{
    char        buf[MAXBUF];
    long        cont;
    regmatch_t  matches[2];

    for(;;) {
        if(BIO_gets(cl, buf, MAXBUF) <= 0) {
            syslog(LOG_WARNING, "unexpected chunked EOF: %m");
            return -1;
        }
        strip_eol(buf);
        if(!regexec(&CHUNK_HEAD, buf, 2, matches, 0))
            cont = strtol(buf, NULL, 16);
        else {
            /* not chunk header */
            syslog(LOG_WARNING, "bad chunk header <%s>: %m", buf);
            return -2;
        }
        if(BIO_printf(be, "%s\r\n", buf) <= 0) {
            syslog(LOG_WARNING, "error write chunked: %m");
            return -3;
        }
        if(cont > 0L) {
            if(copy_bin(cl, be, cont, res_bytes)) {
                syslog(LOG_WARNING, "error copy chunk cont: %m");
                return -4;
            }
        } else
            break;
        /* final CRLF */
        if(BIO_gets(cl, buf, MAXBUF) <= 0) {
            syslog(LOG_WARNING, "unexpected after chunk EOF: %m");
            return -5;
        }
        strip_eol(buf);
        if(buf[0])
            syslog(LOG_WARNING, "unexpected after chunk \"%s\"", buf);
        if(BIO_printf(be, "%s\r\n", buf) <= 0) {
            syslog(LOG_WARNING, "error after chunk write: %m");
            return -6;
        }
    }
    /* possibly trailing headers */
    for(;;) {
        if(BIO_gets(cl, buf, MAXBUF) <= 0) {
            syslog(LOG_WARNING, "unexpected post-chunk EOF: %m");
            return -7;
        }
        if(BIO_puts(be, buf) <= 0) {
            syslog(LOG_WARNING, "error post-chunk write: %m");
            return -8;
        }
        strip_eol(buf);
        if(!buf[0])
            break;
    }
    return 0;
}

/*
 * Time-out for read/gets
 * the SSL manual says not to do it, but it works well enough anyway...
 */
static long
bio_callback(BIO *bio, int cmd, const char *argp, int argi, long argl, long ret)
{
    fd_set          socks;
    struct timeval  to;
    int             s;

    if(cmd == BIO_CB_READ) {
        s = (int)BIO_get_callback_arg(bio);
        to.tv_sec = clnt_to;
        to.tv_usec = 0;
        FD_ZERO(&socks);
        FD_SET(s, &socks);
        if(select(s + 1, &socks, NULL, NULL, &to) != 1)
            return -1L;
    }
    return ret;
}

/*
 * Check if the file underlying a BIO is readable
 */
static int
is_readable(BIO *bio)
{
    fd_set          socks;
    struct timeval  to;
    int             s;

    s = BIO_get_fd(bio, NULL);
    to.tv_sec = 0;
    to.tv_usec = 0;
    FD_ZERO(&socks);
    FD_SET(s, &socks);
    return(select(s + 1, &socks, NULL, NULL, &to) > 0);
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
get_headers(BIO *in)
{
    char    **headers, buf[MAXBUF];
    int     res, n;

    /* HTTP/1.1 allows leading CRLF */
    while((res = BIO_gets(in, buf, MAXBUF)) > 0) {
        strip_eol(buf);
        if(buf[0])
            break;
    }
    if(res <= 0)
        return NULL;

    if((headers = (char **)calloc(MAXHEADERS, sizeof(char *))) == NULL) {
        syslog(LOG_WARNING, "headers: out of memory");
        return NULL;
    }

    for(n = 0; n < MAXHEADERS; n++) {
        if((headers[n] = strdup(buf)) == NULL) {
            free_headers(headers);
            syslog(LOG_WARNING, "header: out of memory");
            return NULL;
        }
        if((res = BIO_gets(in, buf, MAXBUF)) <= 0) {
            free_headers(headers);
            syslog(LOG_WARNING, "can't read header");
            return NULL;
        }
        strip_eol(buf);
        if(!buf[0])
            return headers;
    }

    free_headers(headers);
    syslog(LOG_WARNING, "too many headers");
    return NULL;
}

/*
 * Dummy certificate verification
 */
static int
verify_cert(int ok, X509_STORE_CTX *ctx)
{
    return 1;
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

/* Cleanup code. This should really be in the pthread_cleanup_push, except for bugs in some implementations */
#define clean_all() {   \
    if(be != NULL) { BIO_flush(be); BIO_free_all(be); be = NULL; } \
    if(cl != NULL) { BIO_flush(cl); BIO_free_all(cl); cl = NULL; } \
    if(ctx != NULL) { SSL_CTX_free(ctx); ctx = NULL; } \
}

/*
 * handle an HTTP request
 */
void *
thr_http(void *arg)
{
    BIO                 *cl, *be, *bb;
    X509                *a_cert, *x509;
    EVP_PKEY            *a_pkey;
    SSL_CTX             *ctx;
    thr_arg             *a;
    struct in_addr      from_host;
    struct sockaddr_in  *srv;
    int                 cl_11, be_11, res, chunked, n, sock, no_cont, conn_closed;
    char                request[MAXBUF], response[MAXBUF], buf[MAXBUF], url[MAXBUF], **headers,
                        headers_ok[MAXHEADERS], *a_ciphers, v_host[MAXBUF], referer[MAXBUF], u_agent[MAXBUF];
    long                cont, res_bytes;
    time_t              req_start;
    regmatch_t          matches[3];
    struct linger       l;
    GROUP               *grp;

    a = (thr_arg *)arg;
    from_host = a->from_host;
    sock = a->sock;
    n = 1;
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&n, sizeof(n));
    l.l_onoff = 1;
    l.l_linger = 30;
    setsockopt(sock, SOL_SOCKET, SO_LINGER, (void *)&l, sizeof(l));
    a_cert = a->cert;
    a_pkey = a->pkey;
    a_ciphers = a->ciphers;
    n = a->is_ssl;
    free(a);

    if((cl = BIO_new_socket(sock, 1)) == NULL) {
        syslog(LOG_WARNING, "BIO_new_socket failed");
        shutdown(sock, 2);
        close(sock);
        pthread_exit(NULL);
    }
    BIO_set_callback_arg(cl, (char *)sock);
    BIO_set_callback(cl, bio_callback);

    if(n) {
        SSL     *ssl;

        /* setup SSL_CTX */
        ERR_load_crypto_strings();
        ERR_load_SSL_strings();
        OpenSSL_add_all_algorithms();
        if((ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
            syslog(LOG_ERR, "SSL_CTX_new failed - aborted");
            BIO_free_all(cl);
            pthread_exit(NULL);
        }
        if(SSL_CTX_use_certificate(ctx, a_cert) != 1) {
            syslog(LOG_ERR, "SSL_CTX_use_certificate failed - aborted");
            SSL_CTX_free(ctx);
            BIO_free_all(cl);
            pthread_exit(NULL);
        }
        if(SSL_CTX_use_PrivateKey(ctx, a_pkey) != 1) {
            syslog(LOG_ERR, "SSL_CTX_use_PrivateKey failed - aborted");
            SSL_CTX_free(ctx);
            BIO_free_all(cl);
            pthread_exit(NULL);
        }
        if(SSL_CTX_check_private_key(ctx) != 1) {
            syslog(LOG_ERR, "SSL_CTX_check_private_key failed - aborted");
            SSL_CTX_free(ctx);
            BIO_free_all(cl);
            pthread_exit(NULL);
        }
        if(https_headers)
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, verify_cert);
        else
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, verify_cert);
        SSL_CTX_set_verify_depth(ctx, 0);
        SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
        SSL_CTX_set_options(ctx, SSL_OP_ALL);
        if(a_ciphers)
            SSL_CTX_set_cipher_list(ctx, a_ciphers);

        bb = BIO_new_ssl(ctx, 0);
        BIO_set_ssl_mode(bb, 0);
        cl = BIO_push(bb, cl);
        if(BIO_do_handshake(cl) <= 0) {
            /* no need to log every client without a certificate...
            syslog(LOG_WARNING, "BIO_do_handshake with %s failed: %s", inet_ntoa(from_host),
                ERR_error_string(ERR_get_error(), NULL));
            */
            x509 = NULL;
        } else {
            BIO_get_ssl(bb, &ssl);
            if(ssl == NULL) {
                syslog(LOG_WARNING, "BIO_get_ssl failed");
                BIO_free_all(cl);
                SSL_CTX_free(ctx);
                pthread_exit(NULL);
            }
            x509 = SSL_get_peer_certificate(ssl);
        }
    } else {
        ctx = NULL;
        x509 = NULL;
    }

    if((bb = BIO_new(BIO_f_buffer())) == NULL) {
        syslog(LOG_WARNING, "BIO_new(buffer) failed");
        BIO_free_all(cl);
        SSL_CTX_free(ctx);
        pthread_exit(NULL);
    }
    cl = BIO_push(bb, cl);

    be = NULL;

    for(cl_11 = be_11 = 0;;) {
        req_start = time(NULL);
        res_bytes = 0L;
        v_host[0] = referer[0] = u_agent[0] = '\0';
        conn_closed = 0;
        for(n = 0; n < MAXHEADERS; n++)
            headers_ok[n] = 1;
        if((headers = get_headers(cl)) == NULL) {
            if(!cl_11) {
                syslog(LOG_WARNING, "error read from %s: %m", inet_ntoa(from_host));
                err_reply(cl, h500, e500);
            }
            clean_all();
            pthread_exit(NULL);
        }

        /* check for correct request */
        strcpy(request, headers[0]);
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
            syslog(LOG_WARNING, "bad request \"%s\" from %s", request, inet_ntoa(from_host));
            err_reply(cl, h501, e501);
            free_headers(headers);
            clean_all();
            pthread_exit(NULL);
        }
        cl_11 = (request[strlen(request) - 1] == '1');
        strncpy(url, request + matches[2].rm_so, matches[2].rm_eo - matches[2].rm_so);
        url[matches[2].rm_eo - matches[2].rm_so] = '\0';

        /* check other headers */
        for(chunked = 0, cont = 0L, n = 1; n < MAXHEADERS && headers[n]; n++) {
            if(regexec(&HEADER, headers[n], 3, matches, 0)) {
                if(log_level > 0)
                    syslog(LOG_WARNING, "bad header from %s (%s)", inet_ntoa(from_host), headers[n]);
                headers_ok[n] = 0;
                /*
                syslog(LOG_WARNING, "bad header from %s (%s)", inet_ntoa(from_host), headers[n]);
                err_reply(cl, h500, e500);
                free_headers(headers);
                clean_all();
                pthread_exit(NULL);
                */
            } else if(!strncasecmp(headers[n] + matches[1].rm_so, "Host", matches[1].rm_eo - matches[1].rm_so)) {
                strncpy(v_host, headers[n] + matches[2].rm_so, matches[2].rm_eo - matches[2].rm_so);
                v_host[matches[2].rm_eo - matches[2].rm_so] = '\0';
            } else if(!strncasecmp(headers[n] + matches[1].rm_so, "Referer", matches[1].rm_eo - matches[1].rm_so)) {
                strncpy(referer, headers[n] + matches[2].rm_so, matches[2].rm_eo - matches[2].rm_so);
                referer[matches[2].rm_eo - matches[2].rm_so] = '\0';
            } else if(!strncasecmp(headers[n] + matches[1].rm_so, "User-agent", matches[1].rm_eo - matches[1].rm_so)) {
                strncpy(u_agent, headers[n] + matches[2].rm_so, matches[2].rm_eo - matches[2].rm_so);
                u_agent[matches[2].rm_eo - matches[2].rm_so] = '\0';
            } else if(!regexec(&CONN_CLOSED, headers[n], 1, matches, 0))
                conn_closed = 1;
            else if(!regexec(&CHUNKED, headers[n], 1, matches, 0))
                chunked = 1;
            else if(!regexec(&CONT_LEN, headers[n], 2, matches, 0))
                cont = atol(headers[n] + matches[1].rm_so);
        }

        if(be != NULL) {
            if(is_readable(be)) {
                /* The only way it's readable is if it's at EOF, so close it! */
                BIO_free_all(be);
                be = NULL;
            }
        }
        /* check that the requested URL still fits the old back-end */
        if(be != NULL && grp != get_grp(url, &headers[1])) {
            BIO_free_all(be);
            be = NULL;
        }
        while(be == NULL) {
            /* find the session - if any */
            if((srv = get_be(grp = get_grp(url, &headers[1]), from_host, url, &headers[1])) == NULL) {
                err_reply(cl, h503, e503);
                free_headers(headers);
                clean_all();
                pthread_exit(NULL);
            }

            if((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
                syslog(LOG_WARNING, "backend %s:%hd create: %m",
                    inet_ntoa(srv->sin_addr), ntohs(srv->sin_port));
                err_reply(cl, h503, e503);
                free_headers(headers);
                clean_all();
                pthread_exit(NULL);
            }
            if(connect(sock, (struct sockaddr *)srv, (socklen_t)sizeof(*srv)) < 0) {
                syslog(LOG_WARNING, "backend %s:%hd connect: %m",
                    inet_ntoa(srv->sin_addr), ntohs(srv->sin_port));
                close(sock);
                kill_be(srv);
                continue;
            }
            n = 1;
            setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&n, sizeof(n));
            l.l_onoff = 1;
            l.l_linger = 30;
            setsockopt(sock, SOL_SOCKET, SO_LINGER, (void *)&l, sizeof(l));
            if((be = BIO_new_socket(sock, 1)) == NULL) {
                syslog(LOG_WARNING, "BIO_new_socket server failed");
                shutdown(sock, 2);
                close(sock);
                free_headers(headers);
                clean_all();
                pthread_exit(NULL);
            }
            if((bb = BIO_new(BIO_f_buffer())) == NULL) {
                syslog(LOG_WARNING, "BIO_new(buffer) server failed");
                free_headers(headers);
                clean_all();
                pthread_exit(NULL);
            }
            be = BIO_push(bb, be);
        }

        /* send the request */
        for(n = 0; n < MAXHEADERS && headers[n]; n++) {
            if(!headers_ok[n])
                continue;
            if(BIO_printf(be, "%s\r\n", headers[n]) <= 0) {
                syslog(LOG_WARNING, "error write to %s:%hd: %m",
                    inet_ntoa(srv->sin_addr), ntohs(srv->sin_port));
                err_reply(cl, h500, e500);
                free_headers(headers);
                clean_all();
                pthread_exit(NULL);
            }
        }
        free_headers(headers);

        /* if SSL put additional headers for client certificate */
        if(ctx != NULL && https_headers) {
            if(https_header != NULL)
                if(BIO_printf(be, "%s\r\n", https_header) <= 0) {
                    syslog(LOG_WARNING, "error write HTTPSHeader to %s:%hd: %m",
                        inet_ntoa(srv->sin_addr), ntohs(srv->sin_port));
                    err_reply(cl, h500, e500);
                    clean_all();
                    pthread_exit(NULL);
                }
            if(x509 != NULL && (bb = BIO_new(BIO_s_mem())) != NULL) {
                X509_NAME_print(bb, X509_get_subject_name(x509), 16);
                BIO_gets(bb, buf, MAXBUF);
                if(BIO_printf(be, "X-SSL-Subject: %s\r\n", buf) <= 0) {
                    syslog(LOG_WARNING, "error write X-SSL-Subject to %s:%hd: %m",
                        inet_ntoa(srv->sin_addr), ntohs(srv->sin_port));
                    err_reply(cl, h500, e500);
                    BIO_free_all(bb);
                    clean_all();
                    pthread_exit(NULL);
                }

                X509_NAME_print(bb, X509_get_issuer_name(x509), 16);
                BIO_gets(bb, buf, MAXBUF);
                if(BIO_printf(be, "X-SSL-Issuer: %s\r\n", buf) <= 0) {
                    syslog(LOG_WARNING, "error write X-SSL-Issuer to %s:%hd: %m",
                        inet_ntoa(srv->sin_addr), ntohs(srv->sin_port));
                    err_reply(cl, h500, e500);
                    BIO_free_all(bb);
                    clean_all();
                    pthread_exit(NULL);
                }

                ASN1_TIME_print(bb, X509_get_notBefore(x509));
                BIO_gets(bb, buf, MAXBUF);
                if(BIO_printf(be, "X-SSL-notBefore: %s\r\n", buf) <= 0) {
                    syslog(LOG_WARNING, "error write X-SSL-notBefore to %s:%hd: %m",
                        inet_ntoa(srv->sin_addr), ntohs(srv->sin_port));
                    err_reply(cl, h500, e500);
                    BIO_free_all(bb);
                    clean_all();
                    pthread_exit(NULL);
                }

                ASN1_TIME_print(bb, X509_get_notAfter(x509));
                BIO_gets(bb, buf, MAXBUF);
                if(BIO_printf(be, "X-SSL-notAfter: %s\r\n", buf) <= 0) {
                    syslog(LOG_WARNING, "error write X-SSL-notAfter to %s:%hd: %m",
                        inet_ntoa(srv->sin_addr), ntohs(srv->sin_port));
                    err_reply(cl, h500, e500);
                    BIO_free_all(bb);
                    clean_all();
                    pthread_exit(NULL);
                }
                BIO_free_all(bb);
            }
        }
        /* put additional client IP header */
        BIO_printf(be, "X-Forwarded-For: %s\r\n", inet_ntoa(from_host));

        /* final CRLF */
        BIO_puts(be, "\r\n");

        if(cl_11 && chunked) {
            /* had Transfer-encoding: chunked so read/write all the chunks (HTTP/1.1 only) */
            if(copy_chunks(cl, be, NULL)) {
                err_reply(cl, h500, e500);
                clean_all();
                pthread_exit(NULL);
            }
        } else if(cont > 0L) {
            /* had Content-length, so do raw reads/writes for the length */
            if(copy_bin(cl, be, cont, NULL)) {
                syslog(LOG_WARNING, "error copy cont: %m");
                err_reply(cl, h500, e500);
                clean_all();
                pthread_exit(NULL);
            }
        }

        if(BIO_flush(be) != 1) {
            syslog(LOG_WARNING, "error flush to %s:%hd: %m",
                inet_ntoa(srv->sin_addr), ntohs(srv->sin_port));
            err_reply(cl, h500, e500);
            clean_all();
            pthread_exit(NULL);
        }

        if((headers = get_headers(be)) == NULL) {
            syslog(LOG_WARNING, "response error read from %s:%hd: %m",
                inet_ntoa(srv->sin_addr), ntohs(srv->sin_port));
            err_reply(cl, h500, e500);
            clean_all();
            pthread_exit(NULL);
        }

        strcpy(response, headers[0]);
        be_11 = (response[7] == '1');
        /* some response codes (1xx, 204, 304) have no content */
        if(!no_cont && !regexec(&RESP_IGN, response, 0, NULL, 0))
            no_cont = 1;

        for(chunked = 0, cont = 0L, n = 1; n < MAXHEADERS && headers[n]; n++) {
            if(!regexec(&CONN_CLOSED, headers[n], 1, matches, 0))
                conn_closed = 1;
            else if(!regexec(&CHUNKED, headers[n], 1, matches, 0))
                chunked = 1;
            else if(!regexec(&CONT_LEN, headers[n], 2, matches, 0))
                cont = atol(headers[n] + matches[1].rm_so);
        }

        /* possibly record session information (only for cookies) */
        upd_session(grp, &headers[1], srv);

        /* send the response */
        for(n = 0; n < MAXHEADERS && headers[n]; n++) {
            if(BIO_printf(cl, "%s\r\n", headers[n]) <= 0) {
                syslog(LOG_WARNING, "error write to %s: %m", inet_ntoa(from_host));
                free_headers(headers);
                clean_all();
                pthread_exit(NULL);
            }
        }
        free_headers(headers);

        /* final CRLF */
        BIO_puts(cl, "\r\n");

        if(!no_cont) {
            /* ignore this if request was HEAD */
            if(be_11 && chunked) {
                /* had Transfer-encoding: chunked so read/write all the chunks (HTTP/1.1 only) */
                if(copy_chunks(be, cl, &res_bytes)) {
                    /* copy_chunks() has its own error messages */
                    clean_all();
                    pthread_exit(NULL);
                }
            } else if(cont > 0L) {
                /* had Content-length, so do raw reads/writes for the length */
                if(copy_bin(be, cl, cont, &res_bytes)) {
                    syslog(LOG_WARNING, "error copy cont: %m");
                    clean_all();
                    pthread_exit(NULL);
                }
            } else
#ifndef MSDAV
            /* for some mysterious reason MS/IIS doesn't like this at all */
            if(is_readable(be))
#endif
            {
                /* old-style response - content until EOF */
                while((res = BIO_read(be, buf, MAXBUF)) > 0) {
                    if(BIO_write(cl, buf, res) != res) {
                        syslog(LOG_WARNING, "error copy response body: %m");
                        clean_all();
                        pthread_exit(NULL);
                    } else
                        res_bytes += res;
                }
            }
        }

        if(BIO_flush(cl) != 1) {
            syslog(LOG_WARNING, "error flush to %s: %m", inet_ntoa(from_host));
            clean_all();
            pthread_exit(NULL);
        }

        /* log what happened */
        strip_eol(request);
        strip_eol(response);
        switch(log_level) {
        case 1:
            syslog(LOG_NOTICE, "%s %s - %s", inet_ntoa(from_host), request, response);
            break;
        case 2:
            snprintf(buf, sizeof(buf), "%s:%hd", inet_ntoa(srv->sin_addr), ntohs(srv->sin_port));
            syslog(LOG_NOTICE, "%s %s - %s (%s)", inet_ntoa(from_host), request, response, buf);
            break;
        case 3:
            if(v_host[0])
                syslog(LOG_NOTICE, "%s %s - - [%s] \"%s\" %c%c%c %s \"%s\" \"%s\"", v_host, inet_ntoa(from_host),
                    log_time(req_start), request, response[9], response[10], response[11], log_bytes(res_bytes),
                    referer, u_agent);
            else
                syslog(LOG_NOTICE, "%s - - [%s] \"%s\" %c%c%c %s \"%s\" \"%s\"", inet_ntoa(from_host),
                    log_time(req_start), request, response[9], response[10], response[11], log_bytes(res_bytes),
                    referer, u_agent);
        }

        if(!be_11) {
            BIO_free_all(be);
            be = NULL;
        }
        if(!cl_11 || conn_closed)
            break;
    }

    clean_all();
    pthread_exit(NULL);
}
