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

static char *rcs_id = "$Id: pound.c,v 1.0 2002/10/31 15:21:24 roseg Prod roseg $";

/*
 * $Log: pound.c,v $
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
        CHUNK_HEAD,         /* chunk header line */
        RESP_IGN;           /* responses for which we ignore content */

/*
 * handle SIGTERM - exit
 */
static void
h_term(int sig)
{
    syslog(LOG_NOTICE, "received SIGTERM - exiting...");
    exit(0);
}

/*
 * handle SIGPIPE - exit thread
 */
static void
h_pipe(int sig)
{
    pthread_exit(NULL);
}

/*
 * check if address/port are already in use
 */
static int
addr_in_use(struct sockaddr_in *addr)
{
    int sock, res;

    if((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        syslog(LOG_ERR, "check socket create: %m - aborted");
        return 1;
    }
    res = (connect(sock, (struct sockaddr *)addr, (socklen_t)sizeof(*addr)) == 0);
    close(sock);
    return res;
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
    int                 *http_sock, *https_sock, clnt_length, i, max_fd, clnt;
    struct sockaddr_in  h_addr, clnt_addr;
    struct hostent      *host;
    fd_set              socks;
    uid_t               user_id;
    gid_t               group_id;
    FILE                *fpid;
    regex_t             LISTEN_ADDR;
    regmatch_t          matches[3];
    EVP_PKEY            **pkey;
    X509                **x509cert;

#ifndef FACILITY
#define FACILITY    LOG_DAEMON
#endif
    openlog("pound", LOG_CONS, FACILITY);
    syslog(LOG_NOTICE, "starting...");

    signal(SIGTERM, h_term);
    /*
     * to avoid problems with some non-standard SSL clients, Konqueror in particualr
     */
    signal(SIGPIPE, h_pipe);

    config_parse(argc, argv);

    /* prepare regular expressions */
    if(
#ifdef  MSDAV
       regcomp(&HTTP, "^(GET|POST|HEAD) ([A-Za-z0-9~;/?:%@&=+$,_.!'(){}-]+) HTTP/1.[01]$",
        REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&XHTTP, "^(PUT|DELETE) ([A-Za-z0-9~;/?:%@&=+$,_.!'(){}-]+) HTTP/1.[01]$",
        REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&WEBDAV, "^(LOCK|UNLOCK|SUBSCRIBE|PROPFIND|PROPPATCH|BPROPPATCH|SEARCH|POLL|MKCOL|MOVE|BMOVE|COPY|BCOPY|DELETE|BDELETE|CONNECT|OPTIONS|TRACE) ([A-Za-z0-9~;/?:%@&=+$,_.!'(){}-]+) HTTP/1.[01]$",
        REG_ICASE | REG_NEWLINE | REG_EXTENDED)
#else
       regcomp(&HTTP, "^(GET|POST|HEAD) ([A-Za-z0-9~;/?:%@&=+$,_.!'()-]+) HTTP/1.[01]$",
        REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&XHTTP, "^(PUT|DELETE) ([A-Za-z0-9~;/?:%@&=+$,_.!'()-]+) HTTP/1.[01]$",
        REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&WEBDAV, "^(LOCK|UNLOCK|SUBSCRIBE|PROPFIND|PROPPATCH|BPROPPATCH|SEARCH|POLL|MKCOL|MOVE|BMOVE|COPY|BCOPY|DELETE|BDELETE|CONNECT|OPTIONS|TRACE) ([A-Za-z0-9~;/?:%@&=+$,_.!'()-]+) HTTP/1.[01]$",
        REG_ICASE | REG_NEWLINE | REG_EXTENDED)
#endif
    || regcomp(&HEADER, "^[A-Za-z][A-Za-z0-9_-]*:.*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&CHUNKED, "^Transfer-encoding: chunked$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&CHUNK_HEAD, "^([0-9a-f]+).*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&CONT_LEN, "^Content-length: ([1-9][0-9]*)$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&LISTEN_ADDR, "^([^,]+),([1-9][0-9]*)$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&RESP_IGN, "^HTTP/1.[01] (10[1-9]|1[1-9][0-9]|204|304).*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    ) {
        syslog(LOG_ERR, "bad Regex - aborted");
        exit(1);
    }

    max_fd = 0;

    /* get HTTP address and port */
    if(http[0]) {
        for(i = 0; http[i]; i++)
            ;
        if((http_sock = (int *)malloc(sizeof(int) * i)) == NULL) {
            syslog(LOG_ERR, "http_sock out of memory - aborted");
            exit(1);
        }
        for(i = 0; http[i]; i++) {
            memset(&h_addr, 0, sizeof(h_addr));
            h_addr.sin_family = AF_INET;

            /* host */
            if(regexec(&LISTEN_ADDR, http[i], 3, matches, 0)) {
                syslog(LOG_ERR, "bad HTTP spec %s - aborted", http[i]);
                exit(1);
            }
            http[i][matches[1].rm_eo] = '\0';
            if((host = gethostbyname(http[i])) == NULL) {
                syslog(LOG_ERR, "Unknown HTTP host %s", http[i]);
                exit(1);
            }
            memcpy(&h_addr.sin_addr.s_addr, host->h_addr_list[0], sizeof(h_addr.sin_addr.s_addr));
            /* port */
            h_addr.sin_port = (in_port_t)htons(atoi(http[i] + matches[2].rm_so));

            if(addr_in_use(&h_addr)) {
                syslog(LOG_WARNING, "%s:%s already in use - skipped", http[i], http[i] + matches[2].rm_so);
                http_sock[i] = -1;
            } else {
                int opt;

                /* prepare the socket */
                if((http_sock[i] = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
                    syslog(LOG_ERR, "HTTP socket create: %m - aborted");
                    exit(1);
                }
                if(http_sock[i] > max_fd)
                    max_fd = http_sock[i];
                opt = 1;
                setsockopt(http_sock[i], SOL_SOCKET, SO_REUSEADDR, (void *)&opt, sizeof(opt));
                if(bind(http_sock[i], (struct sockaddr *)&h_addr, (socklen_t)sizeof(h_addr)) < 0) {
                    syslog(LOG_ERR, "HTTP socket bind: %m - aborted");
                    exit(1);
                }
                listen(http_sock[i], 256);
            }
        }
    }

    /* get HTTPS address and port */
    if(https[0]) {
        FILE    *fcert;

        for(i = 0; https[i]; i++)
            ;
        if((https_sock = (int *)malloc(sizeof(int) * i)) == NULL) {
            syslog(LOG_ERR, "https_sock out of memory - aborted");
            exit(1);
        }
        if((x509cert = (X509 **)malloc(sizeof(X509 *) * i)) == NULL) {
            syslog(LOG_ERR, "cert out of memory - aborted");
            exit(1);
        }
        if((pkey = (EVP_PKEY **)malloc(sizeof(EVP_PKEY *) * i)) == NULL) {
            syslog(LOG_ERR, "pkey out of memory - aborted");
            exit(1);
        }
        for(i = 0; https[i]; i++) {
            memset(&h_addr, 0, sizeof(h_addr));
            h_addr.sin_family = AF_INET;

            /* host */
            if(regexec(&LISTEN_ADDR, https[i], 3, matches, 0)) {
                syslog(LOG_ERR, "bad HTTP spec %s - aborted", https[i]);
                exit(1);
            }
            https[i][matches[1].rm_eo] = '\0';
            if((host = gethostbyname(https[i])) == NULL) {
                syslog(LOG_ERR, "Unknown HTTP host %s", https[i]);
                exit(1);
            }
            memcpy(&h_addr.sin_addr.s_addr, host->h_addr_list[0], sizeof(h_addr.sin_addr.s_addr));
            /* port */
            h_addr.sin_port = (in_port_t)htons(atoi(https[i] + matches[2].rm_so));

            if(addr_in_use(&h_addr)) {
                syslog(LOG_WARNING, "%s:%s already in use - skipped", https[i], https[i] + matches[2].rm_so);
                https_sock[i] = -1;
            } else {
                int opt;

                /* prepare the socket */
                if((https_sock[i] = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
                    syslog(LOG_ERR, "HTTPS socket create: %m - aborted");
                    exit(1);
                }
                if(https_sock[i] > max_fd)
                    max_fd = https_sock[i];
                opt = 1;
                setsockopt(https_sock[i], SOL_SOCKET, SO_REUSEADDR, (void *)&opt, sizeof(opt));
                if(bind(https_sock[i], (struct sockaddr *)&h_addr, (socklen_t)sizeof(h_addr)) < 0) {
                    syslog(LOG_ERR, "HTTPS socket bind: %m - aborted");
                    exit(1);
                }
                listen(https_sock[i], 256);

                /* read the certificate and private key */
                if((fcert = fopen(cert[i], "ra")) == NULL) {
                    syslog(LOG_ERR, "can't open certificate file \"%s\": %m - aborted", cert[i]);
                    exit(1);
                }
                if((x509cert[i] = PEM_read_X509(fcert, NULL, NULL, NULL)) == NULL) {
                    syslog(LOG_ERR, "can't read certificate from file \"%s\"", cert[i]);
                    exit(1);
                }
                rewind(fcert);
                if((pkey[i] = PEM_read_PrivateKey(fcert, NULL, NULL, NULL)) == NULL) {
                    syslog(LOG_ERR, "can't read private key from file \"%s\"", cert[i]);
                    exit(1);
                }
                fclose(fcert);
            }
        }
    }

    max_fd++;

    /* thread stuff */
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    /* set uid if necessary */
    if(user) {
        struct passwd   *pw;

        if((pw = getpwnam(user)) == NULL) {
            syslog(LOG_ERR, "no such user %s - aborted", user);
            exit(1);
        }
        user_id = pw->pw_uid;
    }

    /* set gid if necessary */
    if(group) {
        struct group    *gr;

        if((gr = getgrnam(group)) == NULL) {
            syslog(LOG_ERR, "no such group %s - aborted", group);
            exit(1);
        }
        group_id = gr->gr_gid;
    }

#ifdef  AEMON
    /* daemonize - make ourselves a subprocess. */
    switch (fork()) {
        case 0:
            close(0);
            close(1);
            close(2);
            break;
        case -1:
            syslog(LOG_ERR, "fork: %m - aborted");
            exit(1);
        default:
            exit(0);
    }
#endif

    /* record pid in var/run */
    if((fpid = fopen("/var/run/pound.pid", "wt")) != NULL) {
        fprintf(fpid, "%d\n", getpid());
        fclose(fpid);
    } else
        syslog(LOG_WARNING, "/var/run/pound.pid %m");

    /* chroot if necessary */
    if(root) {
        if(chroot(root)) {
            syslog(LOG_ERR, "chroot: %m - aborted");
            exit(1);
        }
        if(chdir("/")) {
            syslog(LOG_ERR, "chroot/chdir: %m - aborted");
            exit(1);
        }
    }

    if(group)
        if(setgid(group_id) || setegid(group_id)) {
            syslog(LOG_ERR, "setgid: %m - aborted");
            exit(1);
        }
    if(user)
        if(setuid(user_id) || seteuid(user_id)) {
            syslog(LOG_ERR, "setuid: %m - aborted");
            exit(1);
        }

    /* start the pruner */
    if(pthread_create(&thr, &attr, thr_prune, NULL)) {
        syslog(LOG_ERR, "create thr_prune: %m - aborted");
        exit(1);
    }

    /* start resurector (if necessary) */
    if(pthread_create(&thr, &attr, thr_resurect, NULL)) {
        syslog(LOG_ERR, "create thr_resurect: %m - aborted");
        exit(1);
    }

#ifdef  NEED_STACK
    /* set new stack size - necessary for OpenBSD/FreeBSD */
    if(pthread_attr_setstacksize(&attr, 1 << 18)) {
        syslog(LOG_ERR, "can't set stack size - aborted");
        exit(1);
    }
#endif

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
            syslog(LOG_WARNING, "select: %m");
        } else {
            for(i = 0; http[i]; i++) {
                if(http_sock[i] >= 0 && FD_ISSET(http_sock[i], &socks)) {
                    memset(&clnt_addr, 0, sizeof(clnt_addr));
                    clnt_length = sizeof(clnt_addr);
                    if((clnt = accept(http_sock[i], (struct sockaddr *)&clnt_addr, (socklen_t *)&clnt_length)) < 0) {
                        syslog(LOG_WARNING, "HTTP accept: %m");
                    } else if (clnt_addr.sin_family != AF_INET) {
                        /* may happen on FreeBSD, I am told */
                        syslog(LOG_WARNING, "HTTP connection prematurely closed by peer");
                        close(clnt);
                    } else {
                        thr_arg *arg;

                        if((arg = (thr_arg *)malloc(sizeof(thr_arg))) == NULL) {
                            syslog(LOG_WARNING, "HTTP arg: malloc");
                            close(clnt);
                        } else {
                            arg->sock = clnt;
                            arg->from_host = clnt_addr.sin_addr;
                            arg->is_ssl = 0;
                            arg->cert = NULL;
                            arg->pkey = NULL;
                            arg->ciphers = NULL;
                            if(pthread_create(&thr, &attr, thr_http, (void *)arg)) {
                                syslog(LOG_WARNING, "HTTP pthread_create: %m");
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
                    if((clnt = accept(https_sock[i], (struct sockaddr *)&clnt_addr, (socklen_t *)&clnt_length)) < 0) {
                        syslog(LOG_WARNING, "HTTPS accept: %m");
                    } else if (clnt_addr.sin_family != AF_INET) {
                        /* may happen on FreeBSD, I am told */
                        syslog(LOG_WARNING, "HTTPS connection prematurely closed by peer");
                        close(clnt);
                    } else {
                        thr_arg *arg;

                        if((arg = (thr_arg *)malloc(sizeof(thr_arg))) == NULL) {
                            syslog(LOG_WARNING, "HTTPS arg: malloc");
                            close(clnt);
                        } else {
                            arg->sock = clnt;
                            arg->from_host = clnt_addr.sin_addr;
                            arg->is_ssl = 1;
                            arg->cert = x509cert[i];
                            arg->pkey = pkey[i];
                            arg->ciphers = ciphers[i];
                            if(pthread_create(&thr, &attr, thr_http, (void *)arg)) {
                                syslog(LOG_WARNING, "HTTPS pthread_create: %m");
                                free(arg);
                                close(clnt);
                            }
                        }
                    }
                }
            }
        }
    }
}
