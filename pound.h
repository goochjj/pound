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

/*
 * $Id: pound.h,v 1.4 2003/04/24 13:40:12 roseg Exp $
 * Revision 1.0  2002/10/31 15:21:25  roseg
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
 * Revision 0.7  2002/07/23 03:11:28  roseg
 * Moved entirely to BIO (rather then the old comm_)
 * Added HTTPS-specific headers
 * Fixed a few minor problems in the pattern matching
 *
 * Revision 0.6  2002/07/16 21:14:01  roseg
 * added URL groups and matching
 * extended URL reuest matching
 * moved to "modern" regex
 *
 * Revision 0.5  2002/07/04 12:23:42  roseg
 * code split
 *
 */

#include    "config.h"
#include    <stdio.h>

#if HAVE_STDLIB_H
#include    <stdlib.h>
#else
#error "Pound needs stdlib.h"
#endif

#if HAVE_UNISTD_H
#include    <unistd.h>
#else
#error "Pound needs unistd.h"
#endif

#if HAVE_PTHREAD_H
#include    <pthread.h>
#else
#error "Pound needs pthread.h"
#endif

#if HAVE_STRING_H
#include    <string.h>
#else
#error "Pound needs string.h"
#endif

#if TIME_WITH_SYS_TIME
#if HAVE_SYS_TIME_H
#include    <sys/time.h>
#else
#error "Pound needs sys/time.h"
#endif
#if HAVE_TIME_H
#include    <time.h>
#else
#error "Pound needs time.h"
#endif
#else   /* may not mix sys/time.h and time.h */
#if HAVE_SYS_TIME_H
#include    <sys/time.h>
#elif   HAVE_TIME_H
#include    <time.h>
#else
#error "Pound needs time.h"
#endif
#endif  /* mix */

#if HAVE_SYS_TYPES_H
#include    <sys/types.h>
#else
#error "Pound needs sys/types.h"
#endif

#if HAVE_SYS_SOCKET_H
#include    <sys/socket.h>
#else
#error "Pound needs sys/socket.h"
#endif

#if HAVE_NETINET_IN_H
#include    <netinet/in.h>
#else
#error "Pound needs netinet/in.h"
#endif

#if HAVE_ARPA_INET_H
#include    <arpa/inet.h>
#else
#error "Pound needs arpa/inet.h"
#endif

#if HAVE_NETDB_H
#include    <netdb.h>
#else
#error "Pound needs netdb.h"
#endif

#if HAVE_OPENSSL_SSL_H
#define OPENSSL_THREAD_DEFINES
#include    <openssl/ssl.h>
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
#ifndef OPENSSL_THREADS
#error  "Pound requires OpenSSL with thread support"
#endif
#else
#ifndef THREADS
#error  "Pound requires OpenSSL with thread support"
#endif
#endif
#else
#error "Pound needs openssl/ssl.h"
#endif

#if HAVE_OPENSSL_ENGINE_H
#include    <openssl/engine.h>
#endif

#if HAVE_PWD_H
#include    <pwd.h>
#else
#error "Pound needs pwd.h"
#endif

#if HAVE_GRP_H
#include    <grp.h>
#else
#error "Pound needs grp.h"
#endif

#if HAVE_SYSLOG_H
#include    <syslog.h>
#else
#error "Pound needs syslog.h"
#endif

#if HAVE_SIGNAL_H
#include    <signal.h>
#else
#error "Pound needs signal.h"
#endif

#if HAVE_REGEX_H
#include    <regex.h>
#else
#error "Pound needs regex.h"
#endif

#if HAVE_CTYPE_H
#include    <ctype.h>
#else
#error "Pound needs ctype.h"
#endif

#if HAVE_ERRNO_H
#include    <errno.h>
#else
#error "Pound needs errno.h"
#endif

#if HAVE_WAIT_H
#include    <wait.h>
#elif   HAVE_SYS_WAIT_H
#include    <sys/wait.h>
#else
#error "Pound needs sys/wait.h"
#endif

#if HAVE_SYS_STAT_H
#include    <sys/stat.h>
#else
#error "Pound needs sys/stat.h"
#endif

#if HAVE_FCNTL_H
#include    <fcntl.h>
#else
#error "Pound needs fcntl.h"
#endif

extern int errno;

/*
 * Global variables needed by everybody
 */

extern int  clnt_to;            /* client timeout */
extern int  server_to;          /* server timeout */
extern int  log_level;          /* logging mode - 0, 1, 2 */
extern int  https_headers;      /* add HTTPS-specific headers */
extern char *https_header;      /* HTTPS-specific header to add */
extern int  allow_xtd;          /* allow extended HTTP - PUT, DELETE */
extern int  allow_dav;          /* allow WebDAV - LOCK, UNLOCK */
extern int  alive_to;           /* check interval for resurrection */
extern char **http,             /* HTTP port to listen on */
            **https,            /* HTTPS port to listen on */
            **cert,             /* certificate file */
            **ciphers,          /* cipher type */
#if HAVE_OPENSSL_ENGINE_H
            *ssl_engine,        /* OpenSSL engine */
#endif
            *user,              /* user to run as */
            *group,             /* group to run as */
            *root;              /* directory to chroot to */

#define MAXBUF      16378
#define MAXHEADERS  256
#define MAXCHAIN    8
#define GLOB_SESS   15

/* Backend definition */
typedef struct {
    struct sockaddr_in  addr;       /* address */
    struct sockaddr_in  alive_addr; /* address for viability port */
    int                 alive;      /* alive check interval */
}   BACKEND;

/* session key max size */
#define KEY_SIZE    63

/* Session definition */
typedef struct _sess {
    char    key[KEY_SIZE + 1];  /* session key */
    int     to_host;            /* backend index */
    time_t  last_acc;           /* time of last access */
    int     children;           /* number of children */
    struct _sess    *left, *right;
}   SESS;

#define n_children(S)   ((S)? (S)->children: 0)

typedef enum    { SessNONE, SessIP, SessURL, SessCOOKIE } SESS_TYPE;

/* URL group definition */
typedef struct _group {
    regex_t         url_pat;            /* pattern to match the URL against */
    regex_t         *head_req;          /* patterns to match the headers against - mandatory */
    int             n_req;              /* how many of them */
    regex_t         *head_deny;         /* patterns to match the headers against - disallowed */
    int             n_deny;             /* how many of them */
    BACKEND         *backend_addr;      /* array of backend servers */
    int             tot_pri;            /* total number of backend servers */
    SESS_TYPE       sess_type;          /* session type: IP, URL or COOKIE */
    regex_t         sess_pat;           /* pattern to match the session id */
    int             sess_to;            /* session timeout */
    pthread_mutex_t mut;                /* group mutex */
    SESS            *sessions;          /* session tree root */
}   GROUP;

extern GROUP    **groups;

typedef struct  {
    int             sock;
    struct in_addr  from_host;
    SSL_CTX         *ctx;
}   thr_arg;                        /* argument to processing threads: socket, origin */

extern regex_t  HTTP,       /* normal HTTP requests: GET, POST, HEAD */
                XHTTP,      /* extended HTTP requests: PUT, DELETE */
                WEBDAV,     /* WebDAV requests: LOCK, UNLOCK, SUBSCRIBE, PROPFIND, PROPPATCH, BPROPPATCH, SEARCH,
                               POLL, MKCOL, MOVE, BMOVE, COPY, BCOPY, DELETE, BDELETE, CONNECT, OPTIONS, TRACE */
                HEADER,     /* Allowed header */
                CHUNKED,    /* Transfer-encoding: chunked header */
                CONT_LEN,   /* Content-length header */
                CONN_CLOSED,/* Connection: closed header */
                CHUNK_HEAD, /* chunk header line */
                RESP_SKIP,  /* responses for which we skip response */
                RESP_IGN;   /* responses for which we ignore content */

extern char *e500,  /* default error 500 page contents */
            *e501,  /* default error 501 page contents */
            *e503;  /* default error 503 page contents */

#ifdef  NEED_INADDRT
/* for oldish Unices - normally this is in /usr/include/netinet/in.h */
typedef u_int32_t   in_addr_t;
#endif

#ifdef  NEED_INPORTT
/* for oldish Unices - normally this is in /usr/include/netinet/in.h */
typedef u_int16_t   in_port_t;
#endif

/*
 * handle an HTTP request
 */
extern void *thr_http(void *);

/*
 * Find the required group for a given URL
 */
GROUP *get_grp(char *, char **);

/*
 * Find the host to connect to
 */
extern struct sockaddr_in *get_be(GROUP *, struct in_addr, char *, char **);

/*
 * (for cookies only) possibly create session based on response headers
 */
extern void upd_session(GROUP *, char **, struct sockaddr_in  *);

/*
 * mark a backend host as dead;
 * do nothing if no resurection code is active
 */
extern void kill_be(struct sockaddr_in *);

/*
 * Prune the expired sessions and dead hosts from the table;
 * runs every session_to seconds (if needed)
 */
extern void *thr_prune(void *);

/*
 * Check if dead hosts returned to life;
 * runs every alive_to seconds
 */
extern void *thr_resurect(void *);

/*
 * Parse arguments/config file
 */
extern void config_parse(int, char **);
