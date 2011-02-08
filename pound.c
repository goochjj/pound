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

static char *rcs_id = "$Id: pound.c,v 1.4 2003/04/24 13:40:12 roseg Exp $";

/*
 * $Log: pound.c,v $
 * Revision 1.4  2003/04/24 13:40:12  roseg
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
 * Revision 1.1  2003/01/09 01:28:40  roseg
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
 * Revision 0.10  2002/09/05 15:31:32  roseg
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
 * Revision 0.5  2002/07/04 12:19:13  roseg
 * added config file option
 * split program into multiple files
 * cleaned some code
 *
 * Revision 0.4  2002/06/25 23:19:40  roseg
 * added backend dead/resurect code
 * added HTTP/1.1 chunked transfer mode
 * added timeouts for clients
 * code restructuring
 *
 * Revision 0.3  2002/06/18 13:38:20  roseg
 * Added HTTP/1.1 handling - much faster
 * Fixed problem with SIGPIPE
 *
 * Revision 0.2  2002/06/03 01:00:53  roseg
 * added HTTP/HTTPS checking
 * added logging
 * fixed a few minor errors
 *
 * Revision 0.1  2002/05/31 15:53:14  roseg
 * Initial release
 *
 */

#include    "pound.h"

/* common variables */
int     clnt_to;            /* client timeout */
int     server_to;          /* server timeout */
int     log_level;          /* logging mode - 0, 1, 2 */
int     https_headers;      /* add HTTPS-specific headers */
char    *https_header;      /* HTTPS-specific header to add */
int     allow_xtd;          /* allow extended HTTP - PUT, DELETE */
int     allow_dav;          /* allow WebDAV - LOCK, UNLOCK */
int     alive_to;           /* allow extended HTTP - PUT, DELETE */
char    **http,             /* HTTP port to listen on */
        **https,            /* HTTPS port to listen on */
        **cert,             /* certificate file */
        **ciphers,          /* cipher types */
#if HAVE_OPENSSL_ENGINE_H
        *ssl_engine,        /* OpenSSL engine */
#endif
        *user,              /* user to run as */
        *group,             /* group to run as */
        *root;              /* directory to chroot to */

GROUP   **groups;           /* addresses of possible back-end servers */

regex_t HTTP,               /* normal HTTP requests: GET, POST, HEAD */
        XHTTP,              /* extended HTTP requests: PUT, DELETE */
        WEBDAV,             /* WebDAV requests: LOCK, UNLOCK, SUBSCRIBE, PROPFIND, PROPPATCH, BPROPPATCH, SEARCH,
                               POLL, MKCOL, MOVE, BMOVE, COPY, BCOPY, DELETE, BDELETE, CONNECT, OPTIONS, TRACE */
        HEADER,             /* Allowed header */
        CHUNKED,            /* Transfer-encoding: chunked header */
        CONT_LEN,           /* Content-length header */
        CONN_CLOSED,        /* Connection: closed header */
        CHUNK_HEAD,         /* chunk header line */
        RESP_SKIP,          /* responses for which we skip response */
        RESP_IGN;           /* responses for which we ignore content */

char    *e500 = "An internal server error occurred. Please try again later.",
        *e501 = "This method may not be used.",
        *e503 = "The service is not available. Please try again later.";

/* worker pid */
static  pid_t               son = 0;

/*
 * OpenSSL thread support stuff
 */
static pthread_mutex_t  *l_array;

static void
l_init(void)
{
    int i;

    if((l_array = (pthread_mutex_t *)calloc(CRYPTO_num_locks(), sizeof(pthread_mutex_t))) == NULL) {
#ifdef  NO_SYSLOG
        fprintf(stderr, "lock init: out of memory - aborted...\n");
#else
        syslog(LOG_ERR, "lock init: out of memory - aborted...");
#endif
        exit(1);
    }
    for(i = 0; i < CRYPTO_num_locks(); i++)
        pthread_mutex_init(&l_array[i], NULL);
    return;
}

static void
l_lock(int mode, int n, const char *file, int line)
{
    if(mode & CRYPTO_LOCK)
        pthread_mutex_lock(&l_array[n]);
    else
        pthread_mutex_unlock(&l_array[n]);
    return;
}

static unsigned long
l_id(void)
{
    return (unsigned long)pthread_self();
}

/*
 * handle SIGTERM - exit
 */
static RETSIGTYPE
h_term(int sig)
{
#ifdef  NO_SYSLOG
    fprintf(stderr, "received signal %d - exiting...\n", sig);
#else
    syslog(LOG_NOTICE, "received signal %d - exiting...", sig);
#endif
    if(son > 0)
        kill(son, SIGTERM);
    exit(0);
}

/*
 * check if address/port are already in use
 */
static int
addr_in_use(struct sockaddr_in *addr)
{
    int sock, res;

    if((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
#ifdef  NO_SYSLOG
        fprintf(stderr, "check socket create: %s - aborted\n", strerror(errno));
#else
        syslog(LOG_ERR, "check socket create: %m - aborted");
#endif
        return 1;
    }
    res = (connect(sock, (struct sockaddr *)addr, (socklen_t)sizeof(*addr)) == 0);
    close(sock);
    return res;
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
 * Pound: the reverse-proxy/load-balancer
 *
 * Arguments:
 *  -f config_file      configuration file - exclusive of other flags
 */

int
main(int argc, char **argv)
{
    pthread_t           thr;
    pthread_attr_t      attr;
    int                 *http_sock, *https_sock, clnt_length, i, n, max_fd, clnt;
    struct sockaddr_in  host_addr, clnt_addr;
    struct hostent      *host;
    fd_set              socks;
    uid_t               user_id;
    gid_t               group_id;
    FILE                *fpid;
    char                fpid_name[32];
    regex_t             LISTEN_ADDR;
    regmatch_t          matches[3];
    SSL_CTX             **ctx;

#ifndef  NO_SYSLOG
#ifndef FACILITY
#define FACILITY    LOG_DAEMON
#endif
    openlog("pound", LOG_CONS, FACILITY);
#endif
#ifdef  NO_SYSLOG
    fprintf(stderr, "starting...\n");
#else
    syslog(LOG_NOTICE, "starting...");
#endif

    signal(SIGTERM, h_term);
    signal(SIGINT, h_term);
    signal(SIGQUIT, h_term);
    signal(SIGPIPE, SIG_IGN);

    config_parse(argc, argv);

#if HAVE_OPENSSL_ENGINE_H
    /* select SSL engine */
    if (ssl_engine != NULL) {
        ENGINE  *e;

        if (!(e = ENGINE_by_id(ssl_engine))) {
#ifdef  NO_SYSLOG
            fprintf(stderr, "could not find %s engine\n", ssl_engine);
#else
            syslog(LOG_ERR, "could not find %s engine", ssl_engine);
#endif
            exit(1);
        }
        if(!ENGINE_init(e)) {
            ENGINE_free(e);
#ifdef  NO_SYSLOG
            fprintf(stderr, "could not init %s engine\n", ssl_engine);
#else
            syslog(LOG_ERR, "could not init %s engine", ssl_engine);
#endif
            exit(1);
        }
        if(!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
            ENGINE_free(e);
#ifdef  NO_SYSLOG
            fprintf(stderr, "could not set all defaults\n");
#else
            syslog(LOG_ERR, "could not set all defaults");
#endif
            exit(1);
        }
        ENGINE_finish(e);
        ENGINE_free(e);
#ifdef  NO_SYSLOG
        fprintf(stderr, "%s engine selected\n", ssl_engine);
#else
        syslog(LOG_NOTICE, "%s engine selected", ssl_engine);
#endif
    }
#endif

    /* prepare regular expressions */
    if(
#ifdef  MSDAV
       regcomp(&HTTP, "^(GET|POST|HEAD) ([A-Za-z0-9~;/?:%@&=+$,_.!'(){}<>#*\"-]+) HTTP/1.[01]$",
        REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&XHTTP, "^(PUT|DELETE) ([A-Za-z0-9~;/?:%@&=+$,_.!'(){}<>#*\"-]+) HTTP/1.[01]$",
        REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&WEBDAV, "^(LOCK|UNLOCK|SUBSCRIBE|PROPFIND|PROPPATCH|BPROPPATCH|SEARCH|POLL|MKCOL|MOVE|BMOVE|COPY|BCOPY|DELETE|BDELETE|CONNECT|OPTIONS|TRACE|MKACTIVITY|CHECKOUT|MERGE|REPORT) ([A-Za-z0-9~;/?:%@&=+$,_.!'(){}<>#*\"-]+) HTTP/1.[01]$",
        REG_ICASE | REG_NEWLINE | REG_EXTENDED)
#else
       regcomp(&HTTP, "^(GET|POST|HEAD) ([A-Za-z0-9~;/?:%@&=+$,_.!'()<>#*\"-]+) HTTP/1.[01]$",
        REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&XHTTP, "^(PUT|DELETE) ([A-Za-z0-9~;/?:%@&=+$,_.!'()<>#*\"-]+) HTTP/1.[01]$",
        REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&WEBDAV, "^(LOCK|UNLOCK) ([A-Za-z0-9~;/?:%@&=+$,_.!'()<>#*\"-]+) HTTP/1.[01]$",
        REG_ICASE | REG_NEWLINE | REG_EXTENDED)
#endif
    || regcomp(&HEADER, "^([A-Za-z][A-Za-z0-9_-]*):[ \t]*(.*)$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&CHUNKED, "^Transfer-encoding:[ \t]*chunked$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&CHUNK_HEAD, "^([0-9a-f]+).*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&CONT_LEN, "^Content-length:[ \t]*([1-9][0-9]*)$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&CONN_CLOSED, "^Connection:[ \t]*close$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&LISTEN_ADDR, "^([^,]+),([1-9][0-9]*)$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&RESP_SKIP, "^HTTP/1.1 100.*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&RESP_IGN, "^HTTP/1.[01] (10[1-9]|1[1-9][0-9]|204|304).*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    ) {
#ifdef  NO_SYSLOG
        fprintf(stderr, "bad Regex - aborted\n");
#else
        syslog(LOG_ERR, "bad Regex - aborted");
#endif
        exit(1);
    }

    max_fd = 0;

    /* get HTTP address and port */
    if(http[0]) {
        for(i = 0; http[i]; i++)
            ;
        if((http_sock = (int *)malloc(sizeof(int) * i)) == NULL) {
#ifdef  NO_SYSLOG
            fprintf(stderr, "http_sock out of memory - aborted\n");
#else
            syslog(LOG_ERR, "http_sock out of memory - aborted");
#endif
            exit(1);
        }
        for(i = 0; http[i]; i++) {
            memset(&host_addr, 0, sizeof(host_addr));
            host_addr.sin_family = AF_INET;

            /* host */
            if(regexec(&LISTEN_ADDR, http[i], 3, matches, 0)) {
#ifdef  NO_SYSLOG
                fprintf(stderr, "bad HTTP spec %s - aborted\n", http[i]);
#else
                syslog(LOG_ERR, "bad HTTP spec %s - aborted", http[i]);
#endif
                exit(1);
            }
            http[i][matches[1].rm_eo] = '\0';
            if(strcmp(http[i], "*") == 0) {
                /*
                 * listen on all interfaces
                 */
                host_addr.sin_addr.s_addr = INADDR_ANY;
            } else {
                if((host = gethostbyname(http[i])) == NULL) {
#ifdef  NO_SYSLOG
                    fprintf(stderr, "Unknown HTTP host %s\n", http[i]);
#else
                    syslog(LOG_ERR, "Unknown HTTP host %s", http[i]);
#endif
                    exit(1);
                }
                memcpy(&host_addr.sin_addr.s_addr, host->h_addr_list[0], sizeof(host_addr.sin_addr.s_addr));
            }
            /* port */
            host_addr.sin_port = (in_port_t)htons(atoi(http[i] + matches[2].rm_so));

            if(host_addr.sin_addr.s_addr != INADDR_ANY && addr_in_use(&host_addr)) {
#ifdef  NO_SYSLOG
                fprintf(stderr, "%s:%s already in use - skipped\n", http[i], http[i] + matches[2].rm_so);
#else
                syslog(LOG_WARNING, "%s:%s already in use - skipped", http[i], http[i] + matches[2].rm_so);
#endif
                http_sock[i] = -1;
            } else {
                int opt;

                /* prepare the socket */
                if((http_sock[i] = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
#ifdef  NO_SYSLOG
                    fprintf(stderr, "HTTP socket create: %s - aborted\n", strerror(errno));
#else
                    syslog(LOG_ERR, "HTTP socket create: %m - aborted");
#endif
                    exit(1);
                }
                if(http_sock[i] > max_fd)
                    max_fd = http_sock[i];
                opt = 1;
                setsockopt(http_sock[i], SOL_SOCKET, SO_REUSEADDR, (void *)&opt, sizeof(opt));
                if(bind(http_sock[i], (struct sockaddr *)&host_addr, (socklen_t)sizeof(host_addr)) < 0) {
#ifdef  NO_SYSLOG
                    fprintf(stderr, "HTTP socket bind: %s - aborted\n", strerror(errno));
#else
                    syslog(LOG_ERR, "HTTP socket bind: %m - aborted");
#endif
                    exit(1);
                }
                listen(http_sock[i], 256);
            }
        }
    }

    /* SSL stuff */
    ERR_load_crypto_strings();
    ERR_load_SSL_strings();
    OpenSSL_add_all_algorithms();
    l_init();
    CRYPTO_set_id_callback(l_id);
    CRYPTO_set_locking_callback(l_lock);

    /* get HTTPS address and port */
    if(https[0]) {
        EVP_PKEY    *pkey;
        X509        *x509cert;
        FILE        *fcert;
        int         j;

        for(i = 0; https[i]; i++)
            ;
        if((https_sock = (int *)malloc(sizeof(int) * i)) == NULL) {
#ifdef  NO_SYSLOG
            fprintf(stderr, "https_sock out of memory - aborted\n");
#else
            syslog(LOG_ERR, "https_sock out of memory - aborted");
#endif
            exit(1);
        }
        if((ctx = (SSL_CTX **)malloc(sizeof(SSL_CTX *) * i)) == NULL) {
#ifdef  NO_SYSLOG
            fprintf(stderr, "SSL_CTX out of memory - aborted\n");
#else
            syslog(LOG_ERR, "SSL_CTX out of memory - aborted");
#endif
            exit(1);
        }
        for(i = 0; https[i]; i++) {
            memset(&host_addr, 0, sizeof(host_addr));
            host_addr.sin_family = AF_INET;

            /* host */
            if(regexec(&LISTEN_ADDR, https[i], 3, matches, 0)) {
#ifdef  NO_SYSLOG
                fprintf(stderr, "bad HTTPS spec %s - aborted\n", https[i]);
#else
                syslog(LOG_ERR, "bad HTTPS spec %s - aborted", https[i]);
#endif
                exit(1);
            }
            https[i][matches[1].rm_eo] = '\0';
            if(strcmp(https[i], "*") == 0) {
                /*
                 * listen on all interfaces
                 */
                host_addr.sin_addr.s_addr = INADDR_ANY;
            } else {
                if((host = gethostbyname(https[i])) == NULL) {
#ifdef  NO_SYSLOG
                    fprintf(stderr, "Unknown HTTPS host %s\n", https[i]);
#else
                    syslog(LOG_ERR, "Unknown HTTPS host %s", https[i]);
#endif
                    exit(1);
                }
                memcpy(&host_addr.sin_addr.s_addr, host->h_addr_list[0], sizeof(host_addr.sin_addr.s_addr));
            }
            /* port */
            host_addr.sin_port = (in_port_t)htons(atoi(https[i] + matches[2].rm_so));

            if(host_addr.sin_addr.s_addr != INADDR_ANY && addr_in_use(&host_addr)) {
#ifdef  NO_SYSLOG
                fprintf(stderr, "%s:%s already in use - skipped\n", https[i], https[i] + matches[2].rm_so);
#else
                syslog(LOG_WARNING, "%s:%s already in use - skipped", https[i], https[i] + matches[2].rm_so);
#endif
                https_sock[i] = -1;
            } else {
                int opt;

                /* prepare the socket */
                if((https_sock[i] = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
#ifdef  NO_SYSLOG
                    fprintf(stderr, "HTTPS socket create: %s - aborted\n", strerror(errno));
#else
                    syslog(LOG_ERR, "HTTPS socket create: %m - aborted");
#endif
                    exit(1);
                }
                if(https_sock[i] > max_fd)
                    max_fd = https_sock[i];
                opt = 1;
                setsockopt(https_sock[i], SOL_SOCKET, SO_REUSEADDR, (void *)&opt, sizeof(opt));
                if(bind(https_sock[i], (struct sockaddr *)&host_addr, (socklen_t)sizeof(host_addr)) < 0) {
#ifdef  NO_SYSLOG
                    fprintf(stderr, "HTTPS socket bind: %s - aborted\n", strerror(errno));
#else
                    syslog(LOG_ERR, "HTTPS socket bind: %m - aborted");
#endif
                    exit(1);
                }
                listen(https_sock[i], 256);

                /* setup SSL_CTX */
                if((ctx[i] = SSL_CTX_new(SSLv23_server_method())) == NULL) {
#ifdef  NO_SYSLOG
                    fprintf(stderr, "SSL_CTX_new failed - aborted\n");
#else
                    syslog(LOG_ERR, "SSL_CTX_new failed - aborted");
#endif
                    exit(1);
                }

                if((fcert = fopen(cert[i], "ra")) == NULL) {
#ifdef  NO_SYSLOG
                    fprintf(stderr, "can't open certificate file \"%s\": %s - aborted\n", cert[i], strerror(errno));
#else
                    syslog(LOG_ERR, "can't open certificate file \"%s\": %m - aborted", cert[i]);
#endif
                    exit(1);
                }
                if((x509cert = PEM_read_X509(fcert, NULL, NULL, NULL)) == NULL) {
                    /* at least one certificate */
#ifdef  NO_SYSLOG
                    fprintf(stderr, "can't read certificate from file \"%s\"\n", cert[i]);
#else
                    syslog(LOG_ERR, "can't read certificate from file \"%s\"", cert[i]);
#endif
                    exit(1);
                }

                if(SSL_CTX_use_certificate(ctx[i], x509cert) != 1) {
#ifdef  NO_SYSLOG
                    fprintf(stderr, "SSL_CTX_use_certificate failed - aborted\n");
#else
                    syslog(LOG_ERR, "SSL_CTX_use_certificate failed - aborted");
#endif
                    exit(1);
                }

                /* possibly certificate chain */
                if((x509cert = PEM_read_X509(fcert, NULL, NULL, NULL)) != NULL) {
                    if (ctx[i]->extra_certs != NULL) {
                        sk_X509_pop_free(ctx[i]->extra_certs, X509_free);
                        ctx[i]->extra_certs = NULL;
                    }
                    do {
                        if(SSL_CTX_add_extra_chain_cert(ctx[i], x509cert) != 1) {
#ifdef  NO_SYSLOG
                            fprintf(stderr, "SSL_CTX_add_extra_chain_cert failed - aborted\n");
#else
                            syslog(LOG_ERR, "SSL_CTX_add_extra_chain_cert failed - aborted");
#endif
                            exit(1);
                        }
                    } while((x509cert = PEM_read_X509(fcert, NULL, NULL, NULL)) != NULL);
                }

                /* private key */
                rewind(fcert);
                if((pkey = PEM_read_PrivateKey(fcert, NULL, NULL, NULL)) == NULL) {
#ifdef  NO_SYSLOG
                    fprintf(stderr, "can't read private key from file \"%s\"\n", cert[i]);
#else
                    syslog(LOG_ERR, "can't read private key from file \"%s\"", cert[i]);
#endif
                    exit(1);
                }
                fclose(fcert);

                if(SSL_CTX_use_PrivateKey(ctx[i], pkey) != 1) {
#ifdef  NO_SYSLOG
                    fprintf(stderr, "SSL_CTX_use_PrivateKey failed - aborted\n");
#else
                    syslog(LOG_ERR, "SSL_CTX_use_PrivateKey failed - aborted");
#endif
                    exit(1);
                }
                if(SSL_CTX_check_private_key(ctx[i]) != 1) {
#ifdef  NO_SYSLOG
                    fprintf(stderr, "SSL_CTX_check_private_key failed - aborted\n");
#else
                    syslog(LOG_ERR, "SSL_CTX_check_private_key failed - aborted");
#endif
                    exit(1);
                }

                /* additional CTX setup */
                if(https_headers > 1)
                    SSL_CTX_set_verify(ctx[i], SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_cert);
                else if(https_headers == 1)
                    SSL_CTX_set_verify(ctx[i], SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, verify_cert);
                else
                    SSL_CTX_set_verify(ctx[i], SSL_VERIFY_NONE, verify_cert);
                SSL_CTX_set_verify_depth(ctx[i], 0);
                SSL_CTX_set_mode(ctx[i], SSL_MODE_AUTO_RETRY);
                SSL_CTX_set_options(ctx[i], SSL_OP_ALL);
                if(ciphers[i])
                    SSL_CTX_set_cipher_list(ctx[i], ciphers[i]);
            }
        }
    }

    max_fd++;

    /* set uid if necessary */
    if(user) {
        struct passwd   *pw;

        if((pw = getpwnam(user)) == NULL) {
#ifdef  NO_SYSLOG
            fprintf(stderr, "no such user %s - aborted\n", user);
#else
            syslog(LOG_ERR, "no such user %s - aborted", user);
#endif
            exit(1);
        }
        user_id = pw->pw_uid;
    }

    /* set gid if necessary */
    if(group) {
        struct group    *gr;

        if((gr = getgrnam(group)) == NULL) {
#ifdef  NO_SYSLOG
            fprintf(stderr, "no such group %s - aborted\n", group);
#else
            syslog(LOG_ERR, "no such group %s - aborted", group);
#endif
            exit(1);
        }
        group_id = gr->gr_gid;
    }

#ifdef  AEMON
    /* daemonize - make ourselves a subprocess. */
    switch (fork()) {
        case 0:
#ifndef NO_SYSLOG
            close(0);
            close(1);
            close(2);
#endif
            break;
        case -1:
#ifdef  NO_SYSLOG
            fprintf(stderr, "fork: %s - aborted\n", strerror(errno));
#else
            syslog(LOG_ERR, "fork: %m - aborted");
#endif
            exit(1);
        default:
            exit(0);
    }
#endif

    /* record pid in var/run */
    sprintf(fpid_name, "/var/run/pound_pid.%d", getpid());
    if((fpid = fopen(fpid_name, "wt")) != NULL) {
        fprintf(fpid, "%d\n", getpid());
        fclose(fpid);
    } else
#ifdef  NO_SYSLOG
        fprintf(stderr, "Create \"%s\": %s\n", fpid_name, strerror(errno));
#else
        syslog(LOG_WARNING, "Create \"%s\": %m", fpid_name);
#endif

    /* chroot if necessary */
    if(root) {
        if(chroot(root)) {
#ifdef  NO_SYSLOG
            fprintf(stderr, "chroot: %s - aborted\n", strerror(errno));
#else
            syslog(LOG_ERR, "chroot: %m - aborted");
#endif
            exit(1);
        }
        if(chdir("/")) {
#ifdef  NO_SYSLOG
            fprintf(stderr, "chroot/chdir: %s - aborted\n", strerror(errno));
#else
            syslog(LOG_ERR, "chroot/chdir: %m - aborted");
#endif
            exit(1);
        }
    }

    if(group)
        if(setgid(group_id) || setegid(group_id)) {
#ifdef  NO_SYSLOG
            fprintf(stderr, "setgid: %s - aborted\n", strerror(errno));
#else
            syslog(LOG_ERR, "setgid: %m - aborted");
#endif
            exit(1);
        }
    if(user)
        if(setuid(user_id) || seteuid(user_id)) {
#ifdef  NO_SYSLOG
            fprintf(stderr, "setuid: %s - aborted\n", strerror(errno));
#else
            syslog(LOG_ERR, "setuid: %m - aborted");
#endif
            exit(1);
        }

    /* split off into monitor and working process */
    for(;;)
        if((son = fork()) > 0) {
            int status;

            while(wait(&status) != son)
#ifdef  NO_SYSLOG
                fprintf(stderr, "MONITOR: bad wait (%s)\n", strerror(errno));
#else
                syslog(LOG_ERR, "MONITOR: bad wait (%m)");
#endif
            if(WIFEXITED(status))
#ifdef  NO_SYSLOG
                fprintf(stderr, "MONITOR: worker exited nurmally %d, restarting...\n", WEXITSTATUS(status));
#else
                syslog(LOG_ERR, "MONITOR: worker exited nurmally %d, restarting...", WEXITSTATUS(status));
#endif
            else if(WIFSIGNALED(status))
#ifdef  NO_SYSLOG
                fprintf(stderr, "MONITOR: worker exited on signal %d, restarting...\n", WTERMSIG(status));
#else
                syslog(LOG_ERR, "MONITOR: worker exited on signal %d, restarting...", WTERMSIG(status));
#endif
            else
#ifdef  NO_SYSLOG
                fprintf(stderr, "MONITOR: worker exited (stopped?) %d, restarting...\n", status);
#else
                syslog(LOG_ERR, "MONITOR: worker exited (stopped?) %d, restarting...", status);
#endif
        } else if (son == 0) {
            /* thread stuff */
            pthread_attr_init(&attr);
            pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

#ifdef  NEED_STACK
            /* set new stack size - necessary for OpenBSD/FreeBSD */
            if(pthread_attr_setstacksize(&attr, 1 << 18)) {
#ifdef  NO_SYSLOG
                fprintf(stderr, "can't set stack size - aborted\n");
#else
                syslog(LOG_ERR, "can't set stack size - aborted");
#endif
                exit(1);
            }
#endif

            /* start the pruner */
            if(pthread_create(&thr, &attr, thr_prune, NULL)) {
#ifdef  NO_SYSLOG
                fprintf(stderr, "create thr_prune: %s - aborted\n", strerror(errno));
#else
                syslog(LOG_ERR, "create thr_prune: %m - aborted");
#endif
                exit(1);
            }

            /* start resurector (if necessary) */
            if(pthread_create(&thr, &attr, thr_resurect, NULL)) {
#ifdef  NO_SYSLOG
                fprintf(stderr, "create thr_resurect: %s - aborted\n", strerror(errno));
#else
                syslog(LOG_ERR, "create thr_resurect: %m - aborted");
#endif
                exit(1);
            }

            /* and start working */
            for(;;) {
                FD_ZERO(&socks);
                for(i = 0; http[i]; i++)
                    if(http_sock[i] >= 0)
                        FD_SET(http_sock[i], &socks);
                for(i = 0; https[i]; i++)
                    if(https_sock[i] >= 0)
                        FD_SET(https_sock[i], &socks);
                if((i = select(max_fd, &socks, NULL, NULL, NULL)) < 0) {
#ifdef  NO_SYSLOG
                    fprintf(stderr, "select: %s\n", strerror(errno));
#else
                    syslog(LOG_WARNING, "select: %m");
#endif
                } else {
                    for(i = 0; http[i]; i++) {
                        if(http_sock[i] >= 0 && FD_ISSET(http_sock[i], &socks)) {
                            memset(&clnt_addr, 0, sizeof(clnt_addr));
                            clnt_length = sizeof(clnt_addr);
                            if((clnt = accept(http_sock[i], (struct sockaddr *)&clnt_addr,
                                (socklen_t *)&clnt_length)) < 0) {
#ifdef  NO_SYSLOG
                                fprintf(stderr, "HTTP accept: %s\n", strerror(errno));
#else
                                syslog(LOG_WARNING, "HTTP accept: %m");
#endif
                            } else if (clnt_addr.sin_family != AF_INET) {
                                /* may happen on FreeBSD, I am told */
#ifdef  NO_SYSLOG
                                fprintf(stderr, "HTTP connection prematurely closed by peer\n");
#else
                                syslog(LOG_WARNING, "HTTP connection prematurely closed by peer");
#endif
                                close(clnt);
                            } else {
                                thr_arg *arg;

                                if((arg = (thr_arg *)malloc(sizeof(thr_arg))) == NULL) {
#ifdef  NO_SYSLOG
                                    fprintf(stderr, "HTTP arg: malloc\n");
#else
                                    syslog(LOG_WARNING, "HTTP arg: malloc");
#endif
                                    close(clnt);
                                } else {
                                    arg->sock = clnt;
                                    arg->from_host = clnt_addr.sin_addr;
                                    arg->ctx = NULL;
                                    if(pthread_create(&thr, &attr, thr_http, (void *)arg)) {
#ifdef  NO_SYSLOG
                                        fprintf(stderr, "HTTP pthread_create: %s\n", strerror(errno));
#else
                                        syslog(LOG_WARNING, "HTTP pthread_create: %m");
#endif
                                        free(arg);
                                        close(clnt);
                                    }
                                }
                            }
                        }
                    }
                    for(i = 0; https[i]; i++) {
                        if(https_sock[i] >= 0 && FD_ISSET(https_sock[i], &socks)) {
                            memset(&clnt_addr, 0, sizeof(clnt_addr));
                            clnt_length = sizeof(clnt_addr);
                            if((clnt = accept(https_sock[i], (struct sockaddr *)&clnt_addr,
                                (socklen_t *)&clnt_length)) < 0) {
#ifdef  NO_SYSLOG
                                fprintf(stderr, "HTTPS accept: %s\n", strerror(errno));
#else
                                syslog(LOG_WARNING, "HTTPS accept: %m");
#endif
                            } else if (clnt_addr.sin_family != AF_INET) {
                                /* may happen on FreeBSD, I am told */
#ifdef  NO_SYSLOG
                                fprintf(stderr, "HTTPS connection prematurely closed by peer\n");
#else
                                syslog(LOG_WARNING, "HTTPS connection prematurely closed by peer");
#endif
                                close(clnt);
                            } else {
                                thr_arg *arg;

                                if((arg = (thr_arg *)malloc(sizeof(thr_arg))) == NULL) {
#ifdef  NO_SYSLOG
                                    fprintf(stderr, "HTTPS arg: malloc\n");
#else
                                    syslog(LOG_WARNING, "HTTPS arg: malloc");
#endif
                                    close(clnt);
                                } else {
                                    arg->sock = clnt;
                                    arg->from_host = clnt_addr.sin_addr;
                                    arg->ctx = ctx[i];
                                    if(pthread_create(&thr, &attr, thr_http, (void *)arg)) {
#ifdef  NO_SYSLOG
                                        fprintf(stderr, "HTTPS pthread_create: %s\n", strerror(errno));
#else
                                        syslog(LOG_WARNING, "HTTPS pthread_create: %m");
#endif
                                        free(arg);
                                        close(clnt);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            /* failed to spawn son */
#ifdef  NO_SYSLOG
            fprintf(stderr, "Can't fork worker (%s) - aborted\n", strerror(errno));
#else
            syslog(LOG_ERR, "Can't fork worker (%m) - aborted");
#endif
            exit(1);
        }
}
