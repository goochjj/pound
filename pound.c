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

static char *rcs_id = "$Id: pound.c,v 1.9 2005/06/01 15:01:53 roseg Rel $";

/*
 * $Log: pound.c,v $
 * Revision 1.9  2005/06/01 15:01:53  roseg
 * Enhancements:
 *   Added the VerifyList configuration flag (CA root certs + CRL)
 *   CRL checking code
 *   RewriteRedirect 2 - ignores port value for host matching
 *   Added -c flag (check-only mode)
 *   Added -v flag (verbose mode)
 *   Added -p flag for pid file name
 *
 * Bug fixes:
 *   fixed a potential buffer overflow problem (in checking the Host header)
 *   added call to SSL_library_init
 *   added a check for MSIE before forcing SSL shutdown
 *   X-SSL-Cipher header is added only if HTTPSHeaders is non-zero
 *   added code for shorter linger on badly closed connections (IE work-around)
 *   fixed the locking for session checking (mutex_lock/unlock)
 *
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
char    *ssl_CAlst;         /* CA certificate list (path to file) */
char    *ssl_Verifylst;     /* Verify (path to file) */
int     ssl_vdepth;         /* max verification depth */
int     allow_xtd;          /* allow extended HTTP - PUT, DELETE */
int     allow_dav;          /* allow WebDAV - LOCK, UNLOCK */
int     no_https_11;        /* disallow HTTP/1.1 clients for SSL connections */
int     alive_to;           /* check interval for resurrection */
long    max_req;            /* maximal allowed request size */
char    **http,             /* HTTP port to listen on */
        **https,            /* HTTPS port to listen on */
        **cert,             /* certificate file */
        **ciphers,          /* cipher types */
#if HAVE_OPENSSL_ENGINE_H
        *ssl_engine,        /* OpenSSL engine */
#endif
        *user,              /* user to run as */
        *group,             /* group to run as */
        *root,              /* directory to chroot to */
        *CS_segment,        /* character set of path segment */
        *CS_parm,           /* character set of path parameter */
        *CS_qid,            /* character set of query id */
        *CS_qval,           /* character set of query value */
        *CS_frag;           /* character set of fragment */
int     check_URL;          /* check URL for correct syntax */
int     rewrite_redir;      /* rewrite redirection responses */
int     print_log;          /* print log messages to stdout/stderr */
char    *pid_name;          /* file to record pid in */
regex_t *head_off;          /* headers to remove */
int     n_head_off;         /* how many of them */

GROUP   **groups;           /* addresses of possible back-end servers */

regex_t HTTP,               /* normal HTTP requests: GET, POST, HEAD */
        XHTTP,              /* extended HTTP requests: PUT, DELETE */
        WEBDAV,             /* WebDAV requests: LOCK, UNLOCK, SUBSCRIBE, PROPFIND, PROPPATCH, BPROPPATCH, SEARCH,
                               POLL, MKCOL, MOVE, BMOVE, COPY, BCOPY, DELETE, BDELETE, CONNECT, OPTIONS, TRACE */
        HEADER,             /* Allowed header */
        CHUNK_HEAD,         /* chunk header line */
        RESP_SKIP,          /* responses for which we skip response */
        RESP_IGN,           /* responses for which we ignore content */
        RESP_REDIR,         /* responses for which we rewrite Location */
        LOCATION;           /* the host we are redirected to */

char    *e500 = "An internal server error occurred. Please try again later.",
        *e501 = "This method may not be used.",
        *e503 = "The service is not available. Please try again later.",
        *e414 = "Request URI is too long.";

/* worker pid */
static  pid_t               son = 0;

/*
 * OpenSSL thread support stuff
 */
static pthread_mutex_t  *l_array;

static void
l_init(void)
{
    int i, n_locks;

    n_locks = CRYPTO_num_locks();
    if((l_array = (pthread_mutex_t *)calloc(n_locks, sizeof(pthread_mutex_t))) == NULL) {
        logmsg(LOG_ERR, "lock init: out of memory - aborted...");
        exit(1);
    }
    for(i = 0; i < n_locks; i++)
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
    logmsg(LOG_NOTICE, "received signal %d - exiting...", sig);
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
        logmsg(LOG_ERR, "check socket create: %s - aborted", strerror(errno));
        return 1;
    }
    res = (connect_nb(sock, (struct sockaddr *)addr, (socklen_t)sizeof(*addr)) == 0);
    close(sock);
    return res;
}

/*
 * Dummy certificate verification
 */
static int
verify_cert(int pre_ok, X509_STORE_CTX *ctx)
{
    if(https_headers > 2)
        return 1;

    if(!pre_ok)
        /* we already had an error */
        return 0;

    if(ssl_vdepth > 0 && X509_STORE_CTX_get_error_depth(ctx) > ssl_vdepth) {
        /* certificate chain too long */
        X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_CHAIN_TOO_LONG);
        return 0;
    }

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
    int                 *http_sock, *https_sock, clnt_length, i, n, n_polls, clnt, host_length;
    struct sockaddr_in  host_addr, clnt_addr;
    struct hostent      *host;
    struct pollfd       *polls;
    uid_t               user_id;
    gid_t               group_id;
    FILE                *fpid;
    regex_t             LISTEN_ADDR;
    regmatch_t          matches[3];
    SSL_CTX             **ctx;
    X509_STORE*         store;

    print_log = 0;
#ifndef  NO_SYSLOG
#ifndef FACILITY
#define FACILITY    LOG_DAEMON
#endif
    openlog("pound", LOG_CONS, FACILITY);
#endif
    logmsg(LOG_NOTICE, "starting...");

    signal(SIGTERM, h_term);
    signal(SIGINT, h_term);
    signal(SIGQUIT, h_term);
    signal(SIGPIPE, SIG_IGN);

    config_parse(argc, argv);

    /* SSL stuff */
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    l_init();
    CRYPTO_set_id_callback(l_id);
    CRYPTO_set_locking_callback(l_lock);

#if HAVE_OPENSSL_ENGINE_H
    /* select SSL engine */
    if (ssl_engine != NULL) {
        ENGINE  *e;

#if OPENSSL_VERSION_NUMBER >= 0x00907000L
        ENGINE_load_builtin_engines();
#endif

        if (!(e = ENGINE_by_id(ssl_engine))) {
            logmsg(LOG_ERR, "could not find %s engine", ssl_engine);
            exit(1);
        }
        if(!ENGINE_init(e)) {
            ENGINE_free(e);
            logmsg(LOG_ERR, "could not init %s engine", ssl_engine);
            exit(1);
        }
        if(!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
            ENGINE_free(e);
            logmsg(LOG_ERR, "could not set all defaults");
            exit(1);
        }
        ENGINE_finish(e);
        ENGINE_free(e);
        logmsg(LOG_NOTICE, "%s engine selected", ssl_engine);
    }
#endif

    /* prepare regular expressions */
    if(regcomp(&HTTP, "^(GET|POST|HEAD) ([^ ]+) HTTP/1.[01]$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&XHTTP, "^(PUT|DELETE) ([^ ]+) HTTP/1.[01]$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
#ifdef  MSDAV
    || regcomp(&WEBDAV, "^(LOCK|UNLOCK|SUBSCRIBE|PROPFIND|PROPPATCH|BPROPPATCH|SEARCH|POLL|MKCOL|MOVE|BMOVE|COPY|BCOPY|DELETE|BDELETE|CONNECT|OPTIONS|TRACE|MKACTIVITY|CHECKOUT|MERGE|REPORT) ([^ ]+) HTTP/1.[01]$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
#else
    || regcomp(&WEBDAV, "^(LOCK|UNLOCK) ([^ ]+) HTTP/1.[01]$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
#endif
#ifdef UNSAFE
    || regcomp(&HEADER, "^([A-Za-z0-9_.!#%&'`^~$*+|-]*):[ \t]*(.*)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
#else
    || regcomp(&HEADER, "^([A-Za-z][A-Za-z0-9_-]*):[ \t]*(.*)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
#endif
    || regcomp(&CHUNK_HEAD, "^([0-9a-f]+).*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&LISTEN_ADDR, "^([^,]+),([1-9][0-9]*)$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&RESP_SKIP, "^HTTP/1.1 100.*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&RESP_IGN, "^HTTP/1.[01] (10[1-9]|1[1-9][0-9]|204|30[456]).*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&RESP_REDIR, "^HTTP/1.[01] 30[1237].*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&LOCATION, "(http|https)://([^/]+)/(.*)", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    ) {
        logmsg(LOG_ERR, "bad Regex - aborted");
        exit(1);
    }

    /* get HTTP address and port */
    if(http[0]) {
        for(i = 0; http[i]; i++)
            ;
        if((http_sock = (int *)malloc(sizeof(int) * i)) == NULL) {
            logmsg(LOG_ERR, "http_sock out of memory - aborted");
            exit(1);
        }
        for(i = 0; http[i]; i++) {
            memset(&host_addr, 0, sizeof(host_addr));
            host_addr.sin_family = AF_INET;

            /* host */
            if(regexec(&LISTEN_ADDR, http[i], 3, matches, 0)) {
                logmsg(LOG_ERR, "bad HTTP spec %s - aborted", http[i]);
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
                    logmsg(LOG_ERR, "Unknown HTTP host %s", http[i]);
                    exit(1);
                }
                memcpy(&host_addr.sin_addr.s_addr, host->h_addr_list[0], sizeof(host_addr.sin_addr.s_addr));
            }
            /* port */
            host_addr.sin_port = (in_port_t)htons(atoi(http[i] + matches[2].rm_so));

            if(host_addr.sin_addr.s_addr != INADDR_ANY && addr_in_use(&host_addr)) {
                logmsg(LOG_WARNING, "%s:%s already in use - skipped", http[i], http[i] + matches[2].rm_so);
                http_sock[i] = -1;
            } else {
                int opt;

                /* prepare the socket */
                if((http_sock[i] = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
                    logmsg(LOG_ERR, "HTTP socket create: %s - aborted", strerror(errno));
                    exit(1);
                }
                opt = 1;
                setsockopt(http_sock[i], SOL_SOCKET, SO_REUSEADDR, (void *)&opt, sizeof(opt));
                if(bind(http_sock[i], (struct sockaddr *)&host_addr, (socklen_t)sizeof(host_addr)) < 0) {
                    logmsg(LOG_ERR, "HTTP socket bind: %s - aborted", strerror(errno));
                    exit(1);
                }
                listen(http_sock[i], 512);
            }
        }
    }

    /* get HTTPS address and port */
    if(https[0]) {
        init_RSAgen();

        for(i = 0; https[i]; i++)
            ;
        if((https_sock = (int *)malloc(sizeof(int) * i)) == NULL) {
            logmsg(LOG_ERR, "https_sock out of memory - aborted");
            exit(1);
        }
        if((ctx = (SSL_CTX **)malloc(sizeof(SSL_CTX *) * i)) == NULL) {
            logmsg(LOG_ERR, "SSL_CTX out of memory - aborted");
            exit(1);
        }
        for(i = 0; https[i]; i++) {
            memset(&host_addr, 0, sizeof(host_addr));
            host_addr.sin_family = AF_INET;

            /* host */
            if(regexec(&LISTEN_ADDR, https[i], 3, matches, 0)) {
                logmsg(LOG_ERR, "bad HTTPS spec %s - aborted", https[i]);
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
                    logmsg(LOG_ERR, "Unknown HTTPS host %s", https[i]);
                    exit(1);
                }
                memcpy(&host_addr.sin_addr.s_addr, host->h_addr_list[0], sizeof(host_addr.sin_addr.s_addr));
            }
            /* port */
            host_addr.sin_port = (in_port_t)htons(atoi(https[i] + matches[2].rm_so));

            if(host_addr.sin_addr.s_addr != INADDR_ANY && addr_in_use(&host_addr)) {
                logmsg(LOG_WARNING, "%s:%s already in use - skipped", https[i], https[i] + matches[2].rm_so);
                https_sock[i] = -1;
            } else {
                int     opt;
                char    sess_id[33];

                /* prepare the socket */
                if((https_sock[i] = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
                    logmsg(LOG_ERR, "HTTPS socket create: %s - aborted", strerror(errno));
                    exit(1);
                }
                opt = 1;
                setsockopt(https_sock[i], SOL_SOCKET, SO_REUSEADDR, (void *)&opt, sizeof(opt));
                if(bind(https_sock[i], (struct sockaddr *)&host_addr, (socklen_t)sizeof(host_addr)) < 0) {
                    logmsg(LOG_ERR, "HTTPS socket bind: %s - aborted", strerror(errno));
                    exit(1);
                }
                listen(https_sock[i], 512);

                /* setup SSL_CTX */
                if((ctx[i] = SSL_CTX_new(SSLv23_server_method())) == NULL) {
                    logmsg(LOG_ERR, "SSL_CTX_new failed - aborted");
                    exit(1);
                }

                if(SSL_CTX_use_certificate_chain_file(ctx[i], cert[i]) != 1) {
                    logmsg(LOG_ERR, "SSL_CTX_use_certificate_chain_file failed - aborted");
                    exit(1);
                }
                if(SSL_CTX_use_PrivateKey_file(ctx[i], cert[i], SSL_FILETYPE_PEM) != 1) {
                    logmsg(LOG_ERR, "SSL_CTX_use_PrivateKey_file failed - aborted");
                    exit(1);
                }

                if(SSL_CTX_check_private_key(ctx[i]) != 1) {
                    logmsg(LOG_ERR, "SSL_CTX_check_private_key failed - aborted");
                    exit(1);
                }

                /* additional CTX setup */
                switch(https_headers) {
                case 0:
                    SSL_CTX_set_verify(ctx[i], SSL_VERIFY_NONE, verify_cert);
                    break;
                case 1:
                case 3:
                    SSL_CTX_set_verify(ctx[i], SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, verify_cert);
                    SSL_CTX_set_verify_depth(ctx[i], ssl_vdepth);
                    break;
                case 2:
                    SSL_CTX_set_verify(ctx[i], SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_cert);
                    SSL_CTX_set_verify_depth(ctx[i], ssl_vdepth);
                    break;
                }
                SSL_CTX_set_mode(ctx[i], SSL_MODE_AUTO_RETRY);
                SSL_CTX_set_options(ctx[i], SSL_OP_ALL);

                snprintf(sess_id, 32, "%d-Pound-%d", getpid(), i);
                SSL_CTX_set_session_id_context(ctx[i], sess_id, strlen(sess_id));

                if(ciphers[i])
                    SSL_CTX_set_cipher_list(ctx[i], ciphers[i]);
                SSL_CTX_set_tmp_rsa_callback(ctx[i], RSA_tmp_callback);

                if(ssl_CAlst != NULL) {
                    STACK_OF(X509_NAME) *cert_names;

                    if((cert_names = SSL_load_client_CA_file(ssl_CAlst)) == NULL) {
                        logmsg(LOG_ERR, "SSL_load_client_CA_file failed - aborted");
                        exit(1);
                    }
                    SSL_CTX_set_client_CA_list(ctx[i], cert_names);
                }

                if(ssl_Verifylst != NULL) {
                    if(SSL_CTX_load_verify_locations(ctx[i], ssl_Verifylst, NULL) != 1) {
                        logmsg(LOG_ERR, "SSL_CTX_load_verify_locations failed - aborted");
                        exit(1);
                    }
                }
#if HAVE_X509_STORE_SET_FLAGS
                /* add the CRL stuff */
                if((store = SSL_CTX_get_cert_store(ctx[i])) != NULL)
                    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
                else
                    logmsg(LOG_WARNING, "SSL_CTX_get_cert_store failed!");
#endif
            }
        }
    }

    /* alloc the poll structures */
    n_polls = 0;
    for(i = 0; http[i]; i++)
        if(http_sock[i] >= 0)
            n_polls++;
    for(i = 0; https[i]; i++)
        if(https_sock[i] >= 0)
            n_polls++;
    if((polls = (struct pollfd *)calloc(n_polls, sizeof(struct pollfd))) == NULL) {
        logmsg(LOG_ERR, "Out of memory for poll - aborted");
        exit(1);
    }
    n = 0;
    for(i = 0; http[i]; i++)
        if(http_sock[i] >= 0)
            polls[n++].fd = http_sock[i];
    for(i = 0; https[i]; i++)
        if(https_sock[i] >= 0)
            polls[n++].fd = https_sock[i];

    /* set uid if necessary */
    if(user) {
        struct passwd   *pw;

        if((pw = getpwnam(user)) == NULL) {
            logmsg(LOG_ERR, "no such user %s - aborted", user);
            exit(1);
        }
        user_id = pw->pw_uid;
    }

    /* set gid if necessary */
    if(group) {
        struct group    *gr;

        if((gr = getgrnam(group)) == NULL) {
            logmsg(LOG_ERR, "no such group %s - aborted", group);
            exit(1);
        }
        group_id = gr->gr_gid;
    }

    /* Turn off verbose messages (if necessary) */
    print_log = 0;

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
            logmsg(LOG_ERR, "fork: %s - aborted", strerror(errno));
            exit(1);
        default:
            exit(0);
    }
#endif

    /* record pid in file */
    if((fpid = fopen(pid_name, "wt")) != NULL) {
        fprintf(fpid, "%d\n", getpid());
        fclose(fpid);
    } else
        logmsg(LOG_WARNING, "Create \"%s\": %s", pid_name, strerror(errno));

    /* chroot if necessary */
    if(root) {
        if(chroot(root)) {
            logmsg(LOG_ERR, "chroot: %s - aborted", strerror(errno));
            exit(1);
        }
        if(chdir("/")) {
            logmsg(LOG_ERR, "chroot/chdir: %s - aborted", strerror(errno));
            exit(1);
        }
    }

    if(group)
        if(setgid(group_id) || setegid(group_id)) {
            logmsg(LOG_ERR, "setgid: %s - aborted", strerror(errno));
            exit(1);
        }
    if(user)
        if(setuid(user_id) || seteuid(user_id)) {
            logmsg(LOG_ERR, "setuid: %s - aborted", strerror(errno));
            exit(1);
        }

    /* split off into monitor and working process if necessary */
    for(;;) {
#ifdef  UPER
        if((son = fork()) > 0) {
            int status;

            while(wait(&status) != son)
                logmsg(LOG_ERR, "MONITOR: bad wait (%s)", strerror(errno));
            if(WIFEXITED(status))
                logmsg(LOG_ERR, "MONITOR: worker exited normally %d, restarting...", WEXITSTATUS(status));
            else if(WIFSIGNALED(status))
                logmsg(LOG_ERR, "MONITOR: worker exited on signal %d, restarting...", WTERMSIG(status));
            else
                logmsg(LOG_ERR, "MONITOR: worker exited (stopped?) %d, restarting...", status);
        } else if (son == 0) {
#endif
            /* thread stuff */
            pthread_attr_init(&attr);
            pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

#ifdef  NEED_STACK
            /* set new stack size - necessary for OpenBSD/FreeBSD and Linux NPTL */
            if(pthread_attr_setstacksize(&attr, 1 << 18)) {
                logmsg(LOG_ERR, "can't set stack size - aborted");
                exit(1);
            }
#endif

            /* start the pruner */
            if(pthread_create(&thr, &attr, thr_prune, NULL)) {
                logmsg(LOG_ERR, "create thr_prune: %s - aborted", strerror(errno));
                exit(1);
            }

            /* start resurector (if necessary) */
            if(pthread_create(&thr, &attr, thr_resurect, NULL)) {
                logmsg(LOG_ERR, "create thr_resurect: %s - aborted", strerror(errno));
                exit(1);
            }

            /* start the RSA stuff */
            if(https[0])
                if(pthread_create(&thr, &attr, thr_RSAgen, NULL)) {
                    logmsg(LOG_ERR, "create thr_RSAgen: %s - aborted", strerror(errno));
                    exit(1);
                }

            /* pause to make sure the service threads were started */
            sleep(2);

            /* and start working */
            for(;;) {
                for(i = 0; i < n_polls; i++) {
                    polls[i].events = POLLIN | POLLPRI;
                    polls[i].revents = 0;
                }
                if(poll(polls, n_polls, -1) < 0) {
                    logmsg(LOG_WARNING, "poll: %s", strerror(errno));
                } else {
                    n = -1;
                    for(i = 0; http[i]; i++) {
                        if(http_sock[i] >= 0)
                            n++;
                        if(polls[n].revents & (POLLIN | POLLPRI)) {
                            memset(&clnt_addr, 0, sizeof(clnt_addr));
                            clnt_length = sizeof(clnt_addr);
                            if((clnt = accept(http_sock[i], (struct sockaddr *)&clnt_addr,
                                (socklen_t *)&clnt_length)) < 0) {
                                logmsg(LOG_WARNING, "HTTP accept: %s", strerror(errno));
                            } else if (clnt_addr.sin_family != AF_INET) {
                                /* may happen on FreeBSD, I am told */
                                logmsg(LOG_WARNING, "HTTP connection prematurely closed by peer");
                                close(clnt);
                            } else {
                                thr_arg *arg;

                                if((arg = (thr_arg *)malloc(sizeof(thr_arg))) == NULL) {
                                    logmsg(LOG_WARNING, "HTTP arg: malloc");
                                    close(clnt);
                                } else {
                                    arg->sock = clnt;
                                    arg->from_host = clnt_addr.sin_addr;
                                    memset(&arg->to_host, 0, host_length = sizeof(arg->to_host));
                                    getsockname(http_sock[i], (struct sockaddr *)&arg->to_host, &host_length);
                                    arg->ssl = NULL;
                                    if(pthread_create(&thr, &attr, thr_http, (void *)arg)) {
                                        logmsg(LOG_WARNING, "HTTP pthread_create: %s", strerror(errno));
                                        free(arg);
                                        close(clnt);
                                    }
                                }
                            }
                        }
                    }
                    for(i = 0; https[i]; i++) {
                        if(https_sock[i] >= 0)
                            n++;
                        if(polls[n].revents & (POLLIN | POLLPRI)) {
                            memset(&clnt_addr, 0, sizeof(clnt_addr));
                            clnt_length = sizeof(clnt_addr);
                            if((clnt = accept(https_sock[i], (struct sockaddr *)&clnt_addr,
                                (socklen_t *)&clnt_length)) < 0) {
                                logmsg(LOG_WARNING, "HTTPS accept: %s", strerror(errno));
                            } else if (clnt_addr.sin_family != AF_INET) {
                                /* may happen on FreeBSD, I am told */
                                logmsg(LOG_WARNING, "HTTPS connection prematurely closed by peer");
                                close(clnt);
                            } else {
                                thr_arg *arg;

                                if((arg = (thr_arg *)malloc(sizeof(thr_arg))) == NULL) {
                                    logmsg(LOG_WARNING, "HTTPS arg: malloc");
                                    close(clnt);
                                } else {
                                    arg->sock = clnt;
                                    arg->from_host = clnt_addr.sin_addr;
                                    memset(&arg->to_host, 0, host_length = sizeof(arg->to_host));
                                    getsockname(https_sock[i], (struct sockaddr *)&arg->to_host, &host_length);
                                    if((arg->ssl = SSL_new(ctx[i])) == NULL) {
                                        logmsg(LOG_WARNING, "HTTPS SSL_new: failed");
                                        free(arg);
                                        close(clnt);
                                    }
                                    if(pthread_create(&thr, &attr, thr_http, (void *)arg)) {
                                        logmsg(LOG_WARNING, "HTTPS pthread_create: %s", strerror(errno));
                                        SSL_free(arg->ssl);
                                        free(arg);
                                        close(clnt);
                                    }
                                }
                            }
                        }
                    }
                }
            }
#ifdef  UPER
        } else {
            /* failed to spawn son */
            logmsg(LOG_ERR, "Can't fork worker (%s) - aborted", strerror(errno));
            exit(1);
        }
#endif
    }
}
