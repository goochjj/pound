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

static char *rcs_id = "$Id: svc.c,v 2.0 2006/02/01 11:45:31 roseg Rel $";

/*
 * $Log: svc.c,v $
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
 * Revision 1.10  2006/02/01 11:19:54  roseg
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
 * Revision 1.9  2005/06/01 15:01:54  roseg
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
 * Revision 1.3  2003/02/19 13:52:00  roseg
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
 * Revision 1.0  2002/10/31 15:21:25  roseg
 * fixed ordering of certificate file
 * removed thread auto clean-up (bug in Linux implementation of libpthread)
 * added support for additional WebDAV commands (Microsoft)
 * restructured request match patterns
 * added support for HA ports for back-end hosts
 * added support for optional HTTPS extra header
 *
 * Revision 0.9  2002/09/18 15:07:25  roseg
 * session tracking via IP, URL param, cookie
 * open sockets with REUSEADDR; check first noone else uses them
 * fixed bug in responses without content but Content-length (1xx, 204, 304)
 * added early pruning of sessions to "dead" back-end hosts
 *
 * Revision 0.8  2002/09/05 15:31:32  roseg
 * Added required/disallowed headers matching in groups
 * Configurable cyphers/strength for SSL
 * Fixed bug in multiple requests per connection (GROUP matching)
 * Fixed missing '~' in URL matching
 * Retry request on discovering dead back-end
 * Fixed bug in reading certificate/private-key file
 * Added configure script
 * Configurable logging facility
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
 * Revision 0.5  2002/07/04 12:23:57  roseg
 * code split
 *
 */

#include    "pound.h"

/*
 * Log an error to the syslog or to stderr
 */
#ifdef  HAVE_STDARG_H
void
logmsg(int priority, char *fmt, ...)
{
    char    buf[MAXBUF + 1];
    va_list ap;

    buf[MAXBUF] = '\0';
    va_start(ap, fmt);
    vsnprintf(buf, MAXBUF, fmt, ap);
    va_end(ap);
#ifdef  NO_SYSLOG
    if(priority == LOG_INFO) {
        printf("%s\n", buf);
        fflush(stdout);
    } else {
        char    t_stamp[32];
        time_t  now;

        now = time(NULL);
        strftime(t_stamp, sizeof(t_stamp), "%d/%b/%Y %H:%M:%S %z", localtime(&now));
        fprintf(stderr, "%s: %s\n", t_stamp, buf);
    }
#else
    if(print_log)
        printf("%s\n", buf);
    else
        syslog(log_facility | priority, "%s", buf);
#endif
    return;
}
#else
void
logmsg(int priority, char *fmt, va_alist)
va_dcl
{
    char    buf[MAXBUF + 1];
    va_list ap;

    buf[MAXBUF] = '\0';
    va_start(ap);
    vsnprintf(buf, MAXBUF, fmt, ap);
    va_end(ap);
#ifdef  NO_SYSLOG
    if(priority == LOG_INFO) {
        printf("%s\n", buf);
        fflush(stdout);
    } else {
        char    t_stamp[32];
        time_t  now;

        now = time(NULL);
        strftime(t_stamp, sizeof(t_stamp), "%d/%b/%Y %H:%M:%S %z", localtime(&now));
        fprintf(stderr, "%s: %s\n", t_stamp, buf);
    }
#else
    if(print_log)
        printf("%s\n", buf);
    else
        syslog(log_facility | priority, "%s", buf);
#endif
    return;
}
#endif

/*
 * Parse a header
 * return a code and possibly content in the arg
 */
int
check_header(char *header, char *content)
{
    regmatch_t  matches[4];
    static struct {
        char    header[32];
        int     len;
        int     val;
    } hd_types[] = {
        { "Transfer-encoding",  17, HEADER_TRANSFER_ENCODING },
        { "Content-length",     14, HEADER_CONTENT_LENGTH },
        { "Connection",         10, HEADER_CONNECTION },
        { "Location",           8,  HEADER_LOCATION },
        { "Host",               4,  HEADER_HOST },
        { "Referer",            7,  HEADER_REFERER },
        { "User-agent",         10, HEADER_USER_AGENT },
        { "",                   0,  HEADER_OTHER },
    };
    int i;

    if(!regexec(&HEADER, header, 4, matches, 0)) {
        for(i = 0; hd_types[i].len > 0; i++)
            if((matches[1].rm_eo - matches[1].rm_so) == hd_types[i].len
            && strncasecmp(header + matches[1].rm_so, hd_types[i].header, hd_types[i].len) == 0) {
                /* we know that the original header was read into a buffer of size MAXBUF, so no overflow */
                strncpy(content, header + matches[2].rm_so, matches[2].rm_eo - matches[2].rm_so);
                content[matches[2].rm_eo - matches[2].rm_so] = '\0';
                return hd_types[i].val;
            }
        return HEADER_OTHER;
    } else if(header[0] == ' ' || header[0] == '\t') {
        *content = '\0';
        return HEADER_OTHER;
    } else
        return HEADER_ILLEGAL;
}

/*
 * Find a session in a tree
 */
static SESS *
sess_find(SESS *root, char *key)
{
    int cmp;

    if(root == NULL)
        return NULL;
    if((cmp = strcmp(root->key, key)) == 0)
        return root;
    if(cmp < 0)
        return sess_find(root->left, key);
    return sess_find(root->right, key);
}

/*
 * Add a new session
 */
static SESS *
sess_add(SESS *root, char *key, BACKEND *to_host)
{
    int cmp;

    if(root == NULL) {
        SESS    *res;

        if((res = (SESS *)malloc(sizeof(SESS))) == NULL)
            return NULL;
        strncpy(res->key, key, KEY_SIZE);
        res->to_host = to_host;
        res->last_acc = time(NULL);
        res->children = 1;
        res->left = res->right = NULL;
        return res;
    }
    if((cmp = strcmp(root->key, key)) == 0)
        return root;
    if(cmp < 0)
        root->left = sess_add(root->left, key, to_host);
    else
        root->right = sess_add(root->right, key, to_host);
    root->children = n_children(root->left) + n_children(root->right) + 1;
    return root;
}

static SESS *
sess_del(SESS *root)
{
    SESS    *s;

    if(root->left == NULL) {
        s = root->right;
        free(root);
        return s;
    }
    if(root->right == NULL) {
        s = root->left;
        free(root);
        return s;
    }
    if(root->left->children < root->right->children) {
        for(s = root->right; s->left != NULL; s = s->left)
            s->children += root->left->children;
        s->left = root->left;
        s->children += root->left->children;
        s = root->right;
    } else {
        for(s = root->left; s->right != NULL; s = s->right)
            s->children += root->right->children;
        s->right = root->right;
        s->children += root->right->children;
        s = root->left;
    }
    free(root);
    return s;
}

/*
 * Clean stale (expired) sessions
 */
static SESS *
sess_clean(SESS *root, time_t lim)
{
    if(root == NULL)
        return NULL;
    root->left = sess_clean(root->left, lim);
    root->right = sess_clean(root->right, lim);
    root->children = (root->left? root->left->children: 0) + (root->right? root->right->children: 0) + 1;
    if(root->last_acc >= lim)
        return root;
    return sess_del(root);
}

/*
 * Clean dead back-ends
 */
static SESS *
sess_dead(SESS *root, BACKEND *be)
{
    if(root == NULL)
        return NULL;
    root->left = sess_dead(root->left, be);
    root->right = sess_dead(root->right, be);
    root->children = (root->left? root->left->children: 0) + (root->right? root->right->children: 0) + 1;
    if(root->to_host != be)
        return root;
    return sess_del(root);
}

/*
 * Rebalance the session tree
 */
static SESS *
sess_balance(SESS *root)
{
    SESS    *s;

    if(root == NULL || (root->left == NULL && root->right == NULL))
        return root;
    while(n_children(root->left) < (n_children(root->right) - 1)) {
        s = root->right;
        root->right = s->left;
        s->left = root;
        root = s;
        if(root->left)
            root->left->children = n_children(root->left->left) + n_children(root->left->right) + 1;
        if(root->right)
            root->right->children = n_children(root->right->left) + n_children(root->right->right) + 1;
        root->children = n_children(root->left) + n_children(root->right) + 1;
    }
    while(n_children(root->right) < (n_children(root->left) - 1)) {
        s = root->left;
        root->left = s->right;
        s->right = root;
        root = s;
        if(root->left)
            root->left->children = n_children(root->left->left) + n_children(root->left->right) + 1;
        if(root->right)
            root->right->children = n_children(root->right->left) + n_children(root->right->right) + 1;
        root->children = n_children(root->left) + n_children(root->right) + 1;
    }
    root->left = sess_balance(root->left);
    root->right = sess_balance(root->right);
    return root;
}

static int
match_service(SERVICE *svc, char *request, char **headers)
{
    MATCHER *m;
    int     i, found;

    /* check for request */
    for(m = svc->url; m; m = m->next)
        if(regexec(&m->pat, request, 0, NULL, 0))
            return 0;

    /* check for required headers */
    for(m = svc->req_head; m; m = m->next) {
        for(found = i = 0; i < MAXHEADERS && !found; i++)
            if(headers[i] && !regexec(&m->pat, headers[i], 0, NULL, 0))
                found = 1;
        if(!found)
            return 0;
    }

    /* check for forbidden headers */
    for(m = svc->deny_head; m; m = m->next) {
        for(found = i = 0; i < MAXHEADERS && !found; i++)
            if(headers[i] && !regexec(&m->pat, headers[i], 0, NULL, 0))
                found = 1;
        if(found)
            return 0;
    }

    return 1;
}

/*
 * Find the right service for a request
 */
SERVICE *
get_service(LISTENER *lstn, char *request, char **headers)
{
    SERVICE *svc;

    for(svc = lstn->services; svc; svc = svc->next)
        if(match_service(svc, request, headers))
            return svc;

    /* try global services */
    for(svc = services; svc; svc = svc->next)
        if(match_service(svc, request, headers))
            return svc;

    /* nothing matched */
    return NULL;
}

/*
 * extract the session key for a given request
 */
static int
get_REQUEST(char *res, SERVICE *svc, char *request)
{
    int         n;
    regmatch_t  matches[4];

    if(regexec(&svc->sess_pat, request, 4, matches, 0)) {
        res[0] = '\0';
        return 0;
    }
    if((n = matches[1].rm_eo - matches[1].rm_so) > KEY_SIZE)
        n = KEY_SIZE;
    strncpy(res, request + matches[1].rm_so, n);
    res[n] = '\0';
    return 1;
}

static int
get_HEADERS(char *res, SERVICE *svc, char **headers)
{
    int         i, n;
    regmatch_t  matches[4];

    /* this will match S_COOKIE, S_HEADER and S_BASIC */
    for(i = 0; headers[i]; i++) {
        if(regexec(&svc->sess_pat, headers[i], 4, matches, 0))
            continue;
        if((n = matches[1].rm_eo - matches[1].rm_so) > KEY_SIZE)
            n = KEY_SIZE;
        strncpy(res, headers[i] + matches[1].rm_so, n);
        res[n] = '\0';
        return 1;
    }
    res[0] = '\0';
    return 0;
}

/*
 * Pick a random back-end from a candidate list
 */
static BACKEND *
rand_backend(BACKEND *be, int pri)
{
    while(be) {
        if(!be->alive) {
            be = be->next;
            continue;
        }
        if((pri -= be->priority) < 0)
            break;
        be = be->next;
    }
    return be;
}

/*
 * Find the right back-end for a request
 */
BACKEND *
get_backend(SERVICE *svc, struct in_addr from_host, char *request, char **headers)
{
    BACKEND     *res;
    SESS        *sp;
    char        key[KEY_SIZE + 1];
    in_addr_t   addr;
    int         pri;

    /* blocked */
    if(svc->tot_pri <= 0)
        return NULL;

    pthread_mutex_lock(&svc->mut);
    switch(svc->sess_type) {
    case S_NONE:
        /* choose one back-end randomly */
        res = rand_backend(svc->backends, random() % svc->tot_pri);
        break;
    case S_IP:
        /* "sticky" mappings */
        addr = from_host.s_addr;
        pri = 0;
        while(addr) {
            pri = (pri << 3) ^ (addr & 0xff);
            addr = (addr >> 8);
        }
        res = rand_backend(svc->backends, (addr & 0xffff) % svc->tot_pri);
        break;
    case S_PARM:
        if(get_REQUEST(key, svc, request)) {
            if((sp = sess_find(svc->sessions, key)) == NULL) {
                /* no session yet - create one */
                res = rand_backend(svc->backends, random() % svc->tot_pri);
                svc->sessions = sess_add(svc->sessions, key, res);
            } else
                res = sp->to_host;
        }
        break;
    default:
        /* this works for S_BASIC, S_HEADER and S_COOKIE */
        if(get_HEADERS(key, svc, headers)) {
            if((sp = sess_find(svc->sessions, key)) == NULL) {
                /* no session yet - create one */
                res = rand_backend(svc->backends, random() % svc->tot_pri);
                svc->sessions = sess_add(svc->sessions, key, res);
            } else
                res = sp->to_host;
        } else {
            res = rand_backend(svc->backends, random() % svc->tot_pri);
        }
        break;
    }
    pthread_mutex_unlock(&svc->mut);

    return res;
}

/*
 * (for cookies only) possibly create session based on response headers
 */
void
upd_session(SERVICE *svc, char **headers, BACKEND *be)
{
    char            key[KEY_SIZE + 1];

    pthread_mutex_lock(&svc->mut);
    if(get_HEADERS(key, svc, headers))
        if(sess_find(svc->sessions, key) == NULL)
            svc->sessions = sess_add(svc->sessions, key, be);
    pthread_mutex_unlock(&svc->mut);
    return;
}

/*
 * mark a backend host as dead; remove its sessions
 */
void
kill_be(SERVICE *svc, BACKEND *be)
{
    BACKEND *b;

    pthread_mutex_lock(&svc->mut);
    svc->tot_pri = 0;
    for(b = svc->backends; b; b = b->next) {
        if(b == be)
            b->alive = 0;
        if(b->alive)
            svc->tot_pri += b->priority;
    }
    sess_dead(svc->sessions, be);
    pthread_mutex_unlock(&svc->mut);
    return;
}

/*
 * Find if a redirect needs rewriting
 * In general we have two possibilities that require it:
 * (1) if the redirect was done to the correct location with the wrong protocol
 * (2) if the redirect was done to the back-end rather than the listener
 */
int
need_rewrite(char *location, char *path, LISTENER *lstn, BACKEND *be)
{
    struct sockaddr_in  addr;
    struct hostent      *he;
    regmatch_t          matches[4];
    char                *host, *cp;

    /* split the location into its fields */
    if(regexec(&LOCATION, location, 4, matches, 0))
        return 0;
    host = location + matches[2].rm_so;
    strcpy(path, location + matches[3].rm_so);
    location[matches[1].rm_eo] = location[matches[2].rm_eo] = '\0';
    if((cp = strchr(host, ':')) != NULL)
        *cp = '\0';

    /*
     * Check if the location has the same address as the listener or the back-end
     */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if((he = gethostbyname(host)) == NULL || he->h_addr_list[0] == NULL)
        return 0;
    memcpy(&addr.sin_addr.s_addr, he->h_addr_list[0], sizeof(addr.sin_addr.s_addr));
    if(memcmp(&lstn->addr.sin_addr.s_addr, &addr.sin_addr.s_addr, sizeof(addr.sin_addr.s_addr)) == 0
    || memcmp(&be->addr.sin_addr.s_addr, &addr.sin_addr.s_addr, sizeof(addr.sin_addr.s_addr)) == 0)
        return 1;

    return 0;
}

/*
 * Non-blocking connect(). Does the same as connect(2) but ensures
 * it will time-out after a much shorter time period SERVER_TO
 */
int
connect_nb(int sockfd, struct sockaddr *serv_addr, socklen_t addrlen, int to)
{
    int             flags, res, error;
    socklen_t       len;
    struct pollfd   p;

    if((flags = fcntl(sockfd, F_GETFL, 0)) < 0) {
        logmsg(LOG_ERR, "fcntl GETFL failed: %s", strerror(errno));
        return -1;
    }
    if(fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        logmsg(LOG_ERR, "fcntl SETFL failed: %s", strerror(errno));
        return -1;
    }

    error = 0;
    if((res = connect(sockfd, serv_addr, addrlen)) < 0)
        if(errno != EINPROGRESS)
            return (-1);

    if(res == 0) {
        /* connect completed immediately (usually localhost) */
        if(fcntl(sockfd, F_SETFL, flags) < 0) {
            logmsg(LOG_ERR, "fcntl reSETFL failed: %s", strerror(errno));
            return -1;
        }
        return 0;
    }

    memset(&p, 0, sizeof(p));
    p.fd = sockfd;
    p.events = POLLOUT;
    if((res = poll(&p, 1, to * 1000)) != 1) {
        if(res == 0) {
            /* timeout */
            errno = ETIMEDOUT;
        }
        return -1;
    }

    /* socket is writeable == operation completed */
    len = sizeof(error);
    if(getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        logmsg(LOG_ERR, "getsockopt failed: %s", strerror(errno));
        return -1;
    }

    /* restore file status flags */
    if(fcntl(sockfd, F_SETFL, flags) < 0) {
        logmsg(LOG_ERR, "fcntl reSETFL failed: %s", strerror(errno));
        return -1;
    }

    if(error) {
        /* getsockopt() shows an error */
        errno = error;
        return -1;
    }

    /* really connected */
    return 0;
}

/*
 * Check if dead hosts returned to life;
 * runs every alive seconds
 */
void *
thr_resurect(void *arg)
{
    LISTENER    *lstn;
    SERVICE     *svc;
    BACKEND     *be;
    struct  sockaddr_in  addr, z_addr;
    time_t      last_time, cur_time;
    int         n, sock;

    for(last_time = time(NULL);;) {
        cur_time = time(NULL);
        if((n = alive_to - (cur_time - last_time)) > 0)
            sleep(n);
        last_time = time(NULL);

        /* remove stale sessions */
        for(lstn = listeners; lstn; lstn = lstn->next)
        for(svc = lstn->services; svc; svc = svc->next)
            if(svc->sess_type != S_NONE) {
                pthread_mutex_lock(&svc->mut);
                svc->sessions = sess_clean(svc->sessions, last_time - svc->sess_ttl);
                svc->sessions = sess_balance(svc->sessions);
                pthread_mutex_unlock(&svc->mut);
            }
        for(svc = services; svc; svc = svc->next)
            if(svc->sess_type != S_NONE) {
                pthread_mutex_lock(&svc->mut);
                svc->sessions = sess_clean(svc->sessions, last_time - svc->sess_ttl);
                svc->sessions = sess_balance(svc->sessions);
                pthread_mutex_unlock(&svc->mut);
            }

        /* check hosts still alive - HAport */
        memset(&z_addr, 0, sizeof(z_addr));
        for(lstn = listeners; lstn; lstn = lstn->next)
        for(svc = lstn->services; svc; svc = svc->next)
        for(be = svc->backends; be; be = be->next) {
            if(be->be_type != BACK_END)
                continue;
            if(!be->alive)
                /* already dead */
                continue;
            if(memcmp(&(be->HA), &z_addr, sizeof(z_addr)) == 0)
                /* no HA port */
                continue;
            /* try connecting */
            if((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
                continue;
            if(connect_nb(sock, (struct sockaddr *)&be->HA, (socklen_t)sizeof(be->HA), be->to) != 0) {
                kill_be(svc, be);
                logmsg(LOG_ERR,"BackEnd %s:%hd is dead (HA)", inet_ntoa(be->HA.sin_addr), ntohs(be->HA.sin_port));
            }
            shutdown(sock, 2);
            close(sock);
        }
        for(svc = services; svc; svc = svc->next)
        for(be = svc->backends; be; be = be->next) {
            if(be->be_type != BACK_END)
                continue;
            if(!be->alive)
                /* already dead */
                continue;
            if(memcmp(&(be->HA), &z_addr, sizeof(z_addr)) == 0)
                /* no HA port */
                continue;
            /* try connecting */
            if((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
                continue;
            if(connect_nb(sock, (struct sockaddr *)&be->HA, (socklen_t)sizeof(be->HA), be->to) != 0) {
                kill_be(svc, be);
                logmsg(LOG_ERR,"BackEnd %s:%hd is dead (HA)", inet_ntoa(be->HA.sin_addr), ntohs(be->HA.sin_port));
            }
            shutdown(sock, 2);
            close(sock);
        }
        /* check hosts alive again */
        for(lstn = listeners; lstn; lstn = lstn->next)
        for(svc = lstn->services; svc; svc = svc->next) {
            for(be = svc->backends; be; be = be->next) {
                if(be->be_type != BACK_END)
                    continue;
                if(be->alive)
                    continue;
                if((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
                    continue;
                if(memcmp(&(be->HA), &z_addr, sizeof(z_addr)) == 0)
                    addr = be->addr;
                else
                    addr = be->HA;
                if(connect_nb(sock, (struct sockaddr *)&addr, (socklen_t)sizeof(addr), be->to) == 0) {
                    be->alive = 1;
                    logmsg(LOG_ERR,"BackEnd %s:%hd resurrect",
                        inet_ntoa(be->addr.sin_addr), ntohs(be->addr.sin_port));
                }
                shutdown(sock, 2);
                close(sock);
            }
            pthread_mutex_lock(&svc->mut);
            svc->tot_pri = 0;
            for(be = svc->backends; be; be = be->next)
                if(be->alive)
                    svc->tot_pri += be->priority;
            pthread_mutex_unlock(&svc->mut);
        }
        for(svc = services; svc; svc = svc->next) {
            for(be = svc->backends; be; be = be->next) {
                if(be->be_type != BACK_END)
                    continue;
                if(be->alive)
                    continue;
                if((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
                    continue;
                if(memcmp(&(be->HA), &z_addr, sizeof(z_addr)) == 0)
                    addr = be->addr;
                else
                    addr = be->HA;
                if(connect_nb(sock, (struct sockaddr *)&addr, (socklen_t)sizeof(addr), be->to) == 0) {
                    be->alive = 1;
                    logmsg(LOG_ERR,"BackEnd %s:%hd resurrect",
                        inet_ntoa(be->addr.sin_addr), ntohs(be->addr.sin_port));
                }
                shutdown(sock, 2);
                close(sock);
            }
            pthread_mutex_lock(&svc->mut);
            svc->tot_pri = 0;
            for(be = svc->backends; be; be = be->next)
                if(be->alive)
                    svc->tot_pri += be->priority;
            pthread_mutex_unlock(&svc->mut);
        }
    }
}

static pthread_mutex_t  RSA_mut;                    /* mutex for RSA keygen */
static RSA              *RSA512_keys[N_RSA_KEYS];   /* ephemeral RSA keys */
static RSA              *RSA1024_keys[N_RSA_KEYS];  /* ephemeral RSA keys */

/*
 * return a pre-generated RSA key
 */
RSA *
RSA_tmp_callback(SSL *ssl, int is_export, int keylength)
{
    RSA *res;

    pthread_mutex_lock(&RSA_mut);
    res = (keylength <= 512)? RSA512_keys[rand() % N_RSA_KEYS]: RSA1024_keys[rand() % N_RSA_KEYS];
    pthread_mutex_unlock(&RSA_mut);
    return res;
}

/*
 * Pre-generate ephemeral RSA keys
 */
init_RSAgen()
{
    int n;

    for(n = 0; n < N_RSA_KEYS; n++) {
        if((RSA512_keys[n] = RSA_generate_key(512, RSA_F4, NULL, NULL)) == NULL) {
            logmsg(LOG_ERR,"RSA_generate(%d, 512) failed", n);
            return -1;
        }
        if((RSA1024_keys[n] = RSA_generate_key(1024, RSA_F4, NULL, NULL)) == NULL) {
            logmsg(LOG_ERR,"RSA_generate(%d, 1024) failed", n);
            return -2;
        }
    }
    pthread_mutex_init(&RSA_mut, NULL);
    return 0;
}

/*
 * Periodically regenerate ephemeral RSA keys
 * runs every T_RSA_KEYS seconds
 */
void *
thr_RSAgen(void *arg)
{
    int n;

    for(;;) {
        sleep(T_RSA_KEYS);
        pthread_mutex_lock(&RSA_mut);
        for(n = 0; n < N_RSA_KEYS; n++) {
            RSA_free(RSA512_keys[n]);
            RSA512_keys[n] = RSA_generate_key(512, RSA_F4, NULL, NULL);
            RSA_free(RSA1024_keys[n]);
            RSA1024_keys[n] = RSA_generate_key(1024, RSA_F4, NULL, NULL);
        }
        pthread_mutex_unlock(&RSA_mut);
    }
}
