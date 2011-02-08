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

static char *rcs_id = "$Id: svc.c,v 1.6 2003/11/30 22:56:26 roseg Rel $";

/*
 * $Log: svc.c,v $
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
    if(priority == LOG_INFO)
        printf("%s\n", buf);
    else {
        char    t_stamp[32];
        time_t  now;

        now = time(NULL);
        strftime(t_stamp, sizeof(t_stamp), "%d/%b/%Y %H:%M:%S %z", localtime(&now));
        fprintf(stderr, "%s: %s\n", t_stamp, buf);
    }
#else
    syslog(priority, "%s", buf);
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
    if(priority == LOG_INFO)
        printf("%s\n", buf);
    else {
        char    t_stamp[32];
        time_t  now;

        now = time(NULL);
        strftime(t_stamp, sizeof(t_stamp), "%d/%b/%Y %H:%M:%S %z", localtime(&now));
        fprintf(stderr, "%s: %s\n", t_stamp, buf);
    }
#else
    syslog(priority, "%s", buf);
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
sess_add(SESS *root, char *key, int to_host)
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
sess_dead(SESS *root, int be)
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

/*
 * Find the required group for a given URL and header set
 */
GROUP *
get_grp(char *url, char **headers)
{
    int n, i, j, found;

    for(n = 0; groups[n] != NULL; n++) {
        /* URL */
        if(regexec(&groups[n]->url_pat, url, 0, NULL, 0))
            continue;
        /* required headers */
        for(found = 1, i = 0; found && i < groups[n]->n_req; i++)
        for(found = j = 0; !found && j < (MAXHEADERS - 1) && headers[j]; j++)
            if(!regexec(&groups[n]->head_req[i], headers[j], 0, NULL, 0))
                found = 1;
        if(!found)
            continue;
        /* disallowed headers */
        for(found = 0, i = 0; !found && i < groups[n]->n_deny; i++)
        for(found = j = 0; !found && j < (MAXHEADERS - 1) && headers[j]; j++)
            if(!regexec(&groups[n]->head_deny[i], headers[j], 0, NULL, 0))
                found = 1;
        if(found)
            continue;
        break;
    }
    return groups[n];
}

/*
 * extract the session key for a given request (IP, URL, Headers)
 */
static char *
get_key(GROUP *g, struct in_addr from_host, char *url, char **headers)
{
    static char res_val[KEY_SIZE + 1];
    char        *res;
    regmatch_t  matches[4];
    int         i, n;

    switch(g->sess_type) {
    case SessNONE:
        res = NULL;
        break;
    case SessIP:
        res = inet_ntoa(from_host);
        break;
    case SessURL:
        if(!regexec(&g->sess_pat, url, 4, matches, 0)) {
            if((n = matches[1].rm_eo - matches[1].rm_so) > KEY_SIZE)
                n = KEY_SIZE;
            strncpy(res_val, url + matches[1].rm_so, n);
            res_val[n] = '\0';
            res = res_val;
        } else
            res = NULL;
        break;
    case SessCOOKIE:
    case SessBASIC:
        for(i = 0; headers[i]; i++) {
            if(regexec(&g->sess_pat, headers[i], 4, matches, 0))
                continue;
            if((n = matches[1].rm_eo - matches[1].rm_so) > KEY_SIZE)
                n = KEY_SIZE;
            strncpy(res_val, headers[i] + matches[1].rm_so, n);
            res_val[n] = '\0';
            res = res_val;
            break;
        }
        if(headers[i] == NULL)
            res = NULL;
        break;
    default:
        logmsg(LOG_WARNING, "Unknown session type %d", g->sess_type);
        res = NULL;
    }
    return res;
}

/*
 * Find the host to connect to
 */
struct sockaddr_in *
get_be(GROUP *g, struct in_addr from_host, char *url, char **headers)
{
    struct sockaddr_in  *res;
    SESS                *sp;
    int                 n, orig;
    char                *key;

    if(g == NULL)
        return NULL;

    /* blocked */
    if(g->tot_pri == 0)
        return NULL;

    key = get_key(g, from_host, url, headers);
    if(key != NULL && g->sess_to > 0) {
        /* check for session, add it if necessary */
        pthread_mutex_lock(&g->mut);
        if((sp = sess_find(g->sessions, key)) == NULL) {
            /* no session yet - create one */
            orig = n = rand() % g->tot_pri;
            while(!g->backend_addr[n].alive) {
                n = (n + 1) % g->tot_pri;
                if(n == orig)
                    break;
            }
            if(g->backend_addr[n].alive) {
                g->sessions = sess_add(g->sessions, key, n);
                res = &(g->backend_addr[n].addr);
            } else
                res = NULL;
        } else {
            /* session found */
            if(g->backend_addr[sp->to_host].alive) {
                sp->last_acc = time(NULL);
                res = &(g->backend_addr[sp->to_host].addr);
            } else
                res = NULL;
        }
        pthread_mutex_unlock(&g->mut);
    } else {
        if(g->sess_to < 0) {
            /* "sticky" mappings */
            in_addr_t   t;

            t = from_host.s_addr;
            orig = 0;
            while(t) {
                orig = (orig << 3) ^ (t & 0xff);
                t = (t >> 8);
            }
            orig = n = (orig & 0xffff) % g->tot_pri;
        } else {
            /* just choose a random backend */
            orig = n = rand() % g->tot_pri;
        }
        while(!g->backend_addr[n].alive) {
            n = (n + 1) % g->tot_pri;
            if(n == orig)
                break;
        }
        if(g->backend_addr[n].alive)
            res = &(g->backend_addr[n].addr);
        else
            res = NULL;
    }

    return res;
}

/*
 * (for cookies only) possibly create session based on response headers
 */
void
upd_session(GROUP *g, char **headers, struct sockaddr_in  *srv)
{
    struct in_addr  dummy;
    char            *key;
    int             n;

    memset(&dummy, 0, sizeof(dummy));
    if(g->sess_type != SessCOOKIE || (key = get_key(g, dummy, "", headers)) == NULL)
        return;
    /* probably found a Set-cookie, so we may have to create a session here */
    pthread_mutex_lock(&g->mut);
    if(sess_find(g->sessions, key) == NULL) {
        /* no session yet - create one */
        for(n = 0; n < g->tot_pri; n++)
            if(srv == &(g->backend_addr[n].addr))
                break;
        if(n >= g->tot_pri) {
            logmsg(LOG_WARNING, "upd_session - unknown backend server %s:%hd",
                inet_ntoa(srv->sin_addr), ntohs(srv->sin_port));
            pthread_mutex_unlock(&g->mut);
            return;
        }
        g->sessions = sess_add(g->sessions, key, n);
    }
    pthread_mutex_unlock(&g->mut);
    return;
}

/*
 * mark a backend host as dead;
 * do nothing if no resurection code is active
 */
void
kill_be(struct sockaddr_in *be)
{
    int     i, n;
    GROUP   *g;

    if(alive_to <= 0)
        return;
    for(n = 0; (g = groups[n]) != NULL; n++) {
        pthread_mutex_lock(&g->mut);
        for(i = 0; i < g->tot_pri; i++)
            if(memcmp(&(g->backend_addr[i].addr), be, sizeof(*be)) == 0) {
                g->backend_addr[i].alive = 0;
                g->sessions = sess_dead(g->sessions, i);
            }
        pthread_mutex_unlock(&g->mut);
    }
    return;
}

/*
 * compare two host addresses - only address and port matter
 * this might be a bug in the Linux TCP stack!
 */
static int
addrcmp(struct sockaddr_in *a1, struct sockaddr_in *a2)
{
    int res;

    if((res = memcmp(&a1->sin_addr, &a2->sin_addr, sizeof(a1->sin_addr))))
        return res;
    return memcmp(&a1->sin_port, &a2->sin_port, sizeof(a1->sin_port));
}

/*
 * Find if a host is in our list of back-ends
 */
int
is_be(char *location, struct sockaddr_in *to_host, char *path)
{
    int     i, n;
    GROUP   *g;
    struct sockaddr_in  addr;
    struct hostent      *he;
    regmatch_t          matches[4];
    char                *proto, *host, *port;

    /* split the location into its fields */
    if(regexec(&LOCATION, location, 4, matches, 0))
        return 0;
    proto = location + matches[1].rm_so;
    host = location + matches[2].rm_so;
    strcpy(path, location + matches[3].rm_so);
    location[matches[1].rm_eo] = location[matches[2].rm_eo] = '\0';
    if((port = strchr(host, ':')) != NULL)
        *port++ = '\0';

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if((he = gethostbyname(host)) == NULL)
        return 0;
    memcpy(&addr.sin_addr.s_addr, he->h_addr_list[0], sizeof(addr.sin_addr.s_addr));
    if(port != NULL)
        addr.sin_port = (in_port_t)htons(atoi(port));
    else if(strcmp(proto, "http") == 0)
        addr.sin_port = (in_port_t)htons(80);
    else /* if(strcmp(proto, "https") == 0) */
        addr.sin_port = (in_port_t)htons(443);

    if(addrcmp(to_host, &addr) == 0)
        return 1;
    for(n = 0; (g = groups[n]) != NULL; n++) {
        for(i = 0; i < g->tot_pri; i++)
            if(addrcmp(&(g->backend_addr[i].addr), &addr) == 0)
                return 1;
    }
    return 0;
}

/*
 * Add explicit port number (if required)
 */
char *
add_port(char *host, struct sockaddr_in *to_host)
{
    char    res[MAXBUF];

    if(strchr(host, ':') != NULL)
        /* the host already contains a port */
        return NULL;
    sprintf(res, "Host: %s:%hd", host, ntohs(to_host->sin_port));
    return strdup(res);
}

/*
 * Prune the expired sessions and dead hosts from the table;
 * runs every session_to seconds (if needed)
 */
void *
thr_prune(void *arg)
{
    int     i;
    GROUP   *g;

    for(;;) {
        sleep(GLOB_SESS);
        for(i = 0; (g = groups[i]) != NULL; i++)
            if(g->sess_to > 0) {
                pthread_mutex_lock(&g->mut);
                g->sessions = sess_clean(g->sessions, time(NULL) - g->sess_to);
                g->sessions = sess_balance(g->sessions);
                pthread_mutex_unlock(&g->mut);
            }
    }
}

/*
 * Check if dead hosts returned to life;
 * runs every alive_to seconds (if enabled)
 */
void *
thr_resurect(void *arg)
{
    GROUP   *g;
    int     i, j, n, sock;
    struct  sockaddr_in  addr, z_addr;
    time_t  last_time, cur_time;

    if(alive_to <= 0)
        pthread_exit(NULL);
    for(last_time = time(NULL);;) {
        cur_time = time(NULL);
        if((n = alive_to - (cur_time - last_time)) > 0)
            sleep(n);
        last_time = time(NULL);
        /* check hosts still alive */
        memset(&z_addr, 0, sizeof(z_addr));
        for(n = 0; (g = groups[n]) != NULL; n++) {
            for(i = 0; i < g->tot_pri; i++) {
                if(!g->backend_addr[i].alive)
                    /* already dead */
                    continue;
                if(memcmp(&(g->backend_addr[i].alive_addr), &z_addr, sizeof(z_addr)) == 0)
                    /* no HA port */
                    continue;
                /* try connecting */
                if((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
                    continue;
                addr = g->backend_addr[i].alive_addr;
                if(connect(sock, (struct sockaddr *)&addr, (socklen_t)sizeof(addr)) != 0) {
                    kill_be(&g->backend_addr[i].addr);
                    logmsg(LOG_ERR,"BackEnd %s is dead", inet_ntoa(g->backend_addr[i].addr.sin_addr));
                }
                shutdown(sock, 2);
                close(sock);
            }
        }
        /* check hosts alive again */
        for(n = 0; (g = groups[n]) != NULL; n++) {
            for(i = 0; i < g->tot_pri; i++) {
                if(g->backend_addr[i].alive)
                    continue;
                if((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
                    continue;
                if(memcmp(&(g->backend_addr[i].alive_addr), &z_addr, sizeof(z_addr)) == 0)
                    addr = g->backend_addr[i].addr;
                else
                    addr = g->backend_addr[i].alive_addr;
                if(connect(sock, (struct sockaddr *)&addr, (socklen_t)sizeof(addr)) == 0) {
                    pthread_mutex_lock(&g->mut);
                    addr = g->backend_addr[i].addr;
                    for(j = i; j < g->tot_pri; j++)
                        if(memcmp(&(g->backend_addr[j].addr), &addr, sizeof(addr)) == 0) {
                            g->backend_addr[j].alive = 1;
                            logmsg(LOG_ERR,"BackEnd %s resurrect", inet_ntoa(g->backend_addr[i].addr.sin_addr));
                        }
                    pthread_mutex_unlock(&g->mut);
                }
                shutdown(sock, 2);
                close(sock);
            }
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
 * Periodically regenerate ephemeral RSA keys
 * runs every T_RSA_KEYS seconds
 */
void *
thr_RSAgen(void *arg)
{
    int n;

    pthread_mutex_init(&RSA_mut, NULL);
    pthread_mutex_lock(&RSA_mut);
fprintf(stderr, "start RSA gen\n");
    for(n = 0; n < N_RSA_KEYS; n++) {
        RSA512_keys[n] = RSA_generate_key(512, RSA_F4, NULL, NULL);
        RSA1024_keys[n] = RSA_generate_key(1024, RSA_F4, NULL, NULL);
    }
fprintf(stderr, "done RSA gen\n");
    pthread_mutex_unlock(&RSA_mut);
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
