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

static char *rcs_id = "$Id: pound.c,v 2.0 2006/02/01 11:45:31 roseg Rel $";

/*
 * $Log: pound.c,v $
 * Revision 2.0  2006/02/01 11:45:31  roseg
 * Enhancements:
 *   - new configuration file syntax, offering significant improvements.
 *   - the ability to define listener-specific back-ends. In most cases this
 *     should eliminate the need for multiple Pound instances.
 *   - a new type of back-end: the redirector allows you to respond with a
 *     redirect without involving any back-end server.
 *   - most "secondary" properties (such as error messages, client time-out,
 *     etc.) are now private to listeners.
 *   - HAport has an optional address, different from the main back-end
 *   - added a -V flag for version
 *   - session keeping on a specific Header
 *
 * Revision 1.10  2006/02/01 11:19:53  roseg
 * Enhancements:
 *   added NoDaemon configuration directive (replaces compile-time switch)
 *   added LogFacility configuration directive (replaces compile-time switch)
 *   added user name logging
 *
 * Bug fixes:
 *   fixed problem with the poll() code
 *   fixed problem with empty list in gethostbyname()
 *   added call to setsid() if daemon
 *   conflicting headers are removed (Content-length - Transfer-encoding)
 *
 * Last release in the 1.x series.
 *
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
char        *user,              /* user to run as */
            *group,             /* group to run as */
            *root_jail,         /* directory to chroot to */
            *pid_name;          /* file to record pid in */

int         alive_to,           /* check interval for resurrection */
            daemonize,          /* run as daemon */
            log_facility,       /* log facility to use */
            log_level,          /* logging mode - 0, 1, 2 */
            print_log;          /* print log messages to stdout/stderr */

SERVICE     *services;          /* global services (if any) */

LISTENER    *listeners;         /* all available listeners */

regex_t HTTP,               /* normal HTTP requests: GET, POST, HEAD */
        XHTTP,              /* extended HTTP requests: PUT, DELETE */
        WEBDAV,             /* WebDAV requests: LOCK, UNLOCK, SUBSCRIBE, PROPFIND, PROPPATCH, BPROPPATCH, SEARCH,
                               POLL, MKCOL, MOVE, BMOVE, COPY, BCOPY, DELETE, BDELETE, CONNECT, OPTIONS, TRACE */
        HEADER,             /* Allowed header */
        CHUNK_HEAD,         /* chunk header line */
        RESP_SKIP,          /* responses for which we skip response */
        RESP_IGN,           /* responses for which we ignore content */
        RESP_REDIR,         /* responses for which we rewrite Location */
        LOCATION,           /* the host we are redirected to */
        AUTHORIZATION;      /* the Authorisation header */

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
 * Pound: the reverse-proxy/load-balancer
 *
 * Arguments:
 *  -f config_file      configuration file - exclusive of other flags
 */

int
main(int argc, char **argv)
{
    int                 n_listeners, i, clnt_length, clnt;
    struct pollfd       *polls;
    LISTENER            *lstn;
    pthread_t           thr;
    pthread_attr_t      attr;
    uid_t               user_id;
    gid_t               group_id;
    FILE                *fpid;
    struct sockaddr_in  clnt_addr;

    print_log = 0;
#ifndef  NO_SYSLOG
    openlog("pound", LOG_CONS, LOG_DAEMON);
#endif
    logmsg(LOG_NOTICE, "starting...");

    signal(SIGTERM, h_term);
    signal(SIGINT, h_term);
    signal(SIGQUIT, h_term);
    signal(SIGPIPE, SIG_IGN);

    srandom(getpid());

    /* SSL stuff */
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    l_init();
    CRYPTO_set_id_callback(l_id);
    CRYPTO_set_locking_callback(l_lock);
    init_RSAgen();

    /* read config */
    config_parse(argc, argv);

    /* prepare regular expressions */
    if(regcomp(&HTTP, "^(GET|POST|HEAD) ([^ ]+) HTTP/1.[01]$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&XHTTP, "^(PUT|DELETE) ([^ ]+) HTTP/1.[01]$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
#ifdef  MSDAV
    || regcomp(&WEBDAV, "^(LOCK|UNLOCK|SUBSCRIBE|PROPFIND|PROPPATCH|BPROPPATCH|SEARCH|POLL|MKCOL|MOVE|BMOVE|COPY|BCOPY|DELETE|BDELETE|CONNECT|OPTIONS|TRACE|MKACTIVITY|CHECKOUT|MERGE|REPORT) ([^ ]+) HTTP/1.[01]$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
#else
    || regcomp(&WEBDAV, "^(LOCK|UNLOCK) ([^ ]+) HTTP/1.[01]$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
#endif
    || regcomp(&HEADER, "^([a-z0-9!#$%&'*+.^_`|~-]+):[ \t]*(.*)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&CHUNK_HEAD, "^([0-9a-f]+).*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&RESP_SKIP, "^HTTP/1.1 100.*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&RESP_IGN, "^HTTP/1.[01] (10[1-9]|1[1-9][0-9]|204|30[456]).*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&RESP_REDIR, "^HTTP/1.[01] 30[1237].*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&LOCATION, "(http|https)://([^/]+)/(.*)", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&AUTHORIZATION, "Authorization:[ \t]*Basic[ \t]*([^ \t]*)[ \t]*", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    ) {
        logmsg(LOG_ERR, "bad Regex - aborted");
        exit(1);
    }

    /* open HTTP listeners */
    for(lstn = listeners, n_listeners = 0; lstn; lstn = lstn->next, n_listeners++) {
        int opt;

        /* prepare the socket */
        if((lstn->sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
            logmsg(LOG_ERR, "HTTP socket %s:%hd create: %s - aborted",
                inet_ntoa(lstn->addr.sin_addr), ntohs(lstn->addr.sin_port), strerror(errno));
            exit(1);
        }
        opt = 1;
        setsockopt(lstn->sock, SOL_SOCKET, SO_REUSEADDR, (void *)&opt, sizeof(opt));
        if(bind(lstn->sock, (struct sockaddr *)&lstn->addr, (socklen_t)sizeof(lstn->addr)) < 0) {
            logmsg(LOG_ERR, "HTTP socket bind %s:%hd: %s - aborted",
                inet_ntoa(lstn->addr.sin_addr), ntohs(lstn->addr.sin_port), strerror(errno));
            exit(1);
        }
        listen(lstn->sock, 512);
    }

    /* alloc the poll structures */
    if((polls = (struct pollfd *)calloc(n_listeners, sizeof(struct pollfd))) == NULL) {
        logmsg(LOG_ERR, "Out of memory for poll - aborted");
        exit(1);
    }
    for(lstn = listeners, i = 0; lstn; lstn = lstn->next, i++)
        polls[i].fd = lstn->sock;

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

    if(daemonize) {
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
#ifdef  HAVE_SETSID
        (void) setsid();
#endif
    }

    /* record pid in file */
    if((fpid = fopen(pid_name, "wt")) != NULL) {
        fprintf(fpid, "%d\n", getpid());
        fclose(fpid);
    } else
        logmsg(LOG_WARNING, "Create \"%s\": %s", pid_name, strerror(errno));

    /* chroot if necessary */
    if(root_jail) {
        if(chroot(root_jail)) {
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

            /* start resurector */
            if(pthread_create(&thr, &attr, thr_resurect, NULL)) {
                logmsg(LOG_ERR, "create thr_resurect: %s - aborted", strerror(errno));
                exit(1);
            }

            /* start the RSA stuff */
            if(pthread_create(&thr, &attr, thr_RSAgen, NULL)) {
                logmsg(LOG_ERR, "create thr_RSAgen: %s - aborted", strerror(errno));
                exit(1);
            }

            /* pause to make sure the service threads were started */
            sleep(2);

            /* and start working */
            for(;;) {
                for(i = 0; i < n_listeners; i++) {
                    polls[i].events = POLLIN | POLLPRI;
                    polls[i].revents = 0;
                }
                if(poll(polls, n_listeners, -1) < 0) {
                    logmsg(LOG_WARNING, "poll: %s", strerror(errno));
                } else {
                    for(lstn = listeners, i = 0; lstn; lstn = lstn->next, i++) {
                        if(polls[i].revents & (POLLIN | POLLPRI)) {
                            memset(&clnt_addr, 0, sizeof(clnt_addr));
                            clnt_length = sizeof(clnt_addr);
                            if((clnt = accept(lstn->sock, (struct sockaddr *)&clnt_addr,
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
                                    arg->lstn = lstn;
                                    arg->from_host = clnt_addr.sin_addr;
                                    if(pthread_create(&thr, &attr, thr_http, (void *)arg)) {
                                        logmsg(LOG_WARNING, "HTTP pthread_create: %s", strerror(errno));
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
