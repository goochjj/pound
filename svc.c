/*
 * Pound - the reverse-proxy load-balancer
 * Copyright (C) 2002-2010 Apsis GmbH
 *
 * This file is part of Pound.
 *
 * Pound is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Pound is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Contact information:
 * Apsis GmbH
 * P.O.Box
 * 8707 Uetikon am See
 * Switzerland
 * EMail: roseg@apsis.ch
 */

#include    "pound.h"

#ifndef LHASH_OF
#define LHASH_OF(x) LHASH
#define CHECKED_LHASH_OF(type, h) h
#endif

/*
 * Add a new key/content pair to a hash table
 * the table should be already locked
 */
static void
t_add(LHASH_OF(TABNODE) *const tab, const char *key, const void *content, const size_t cont_len)
{
    TABNODE *t, *old;

    if((t = (TABNODE *)malloc(sizeof(TABNODE))) == NULL) {
        logmsg(LOG_WARNING, "t_add() content malloc");
        return;
    }
    if((t->key = strdup(key)) == NULL) {
        free(t);
        logmsg(LOG_WARNING, "t_add() strdup");
        return;
    }
    if((t->content = malloc(cont_len)) == NULL) {
        free(t->key);
        free(t);
        logmsg(LOG_WARNING, "t_add() content malloc");
        return;
    }
    memcpy(t->content, content, cont_len);
    t->last_acc = time(NULL);
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
    if((old = LHM_lh_insert(TABNODE, tab, t)) != NULL) {
#else
    if((old = (TABNODE *)lh_insert(tab, t)) != NULL) {
#endif
        free(old->key);
        free(old->content);
        free(old);
        logmsg(LOG_WARNING, "t_add() DUP");
    }
    return;
}

/*
 * Find a key
 * returns the content in the parameter
 * side-effect: update the time of last access
 */
static void *
t_find(LHASH_OF(TABNODE) *const tab, char *const key)
{
    TABNODE t, *res;

    t.key = key;
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
    if((res = (TABNODE *)LHM_lh_retrieve(TABNODE, tab, &t)) != NULL) {
#else
    if((res = (TABNODE *)lh_retrieve(tab, &t)) != NULL) {
#endif
        res->last_acc = time(NULL);
        return res->content;
    }
    return NULL;
}

/*
 * Delete a key
 */
static void
t_remove(LHASH_OF(TABNODE) *const tab, char *const key)
{
    TABNODE t, *res;

    t.key = key;
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
    if((res = LHM_lh_delete(TABNODE, tab, &t)) != NULL) {
#else
    if((res = (TABNODE *)lh_delete(tab, &t)) != NULL) {
#endif
        free(res->key);
        free(res->content);
        free(res);
    }
    return;
}

typedef struct  {
    LHASH_OF(TABNODE)   *tab;
    time_t              lim;
    void                *content;
    int                 cont_len;
}   ALL_ARG;

static void
t_old_doall_arg(TABNODE *t, ALL_ARG *a)
{
    TABNODE *res;

    if(t->last_acc < a->lim)
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
        if((res = LHM_lh_delete(TABNODE, a->tab, t)) != NULL) {
#else
        if((res = lh_delete(a->tab, t)) != NULL) {
#endif
            free(res->key);
            free(res->content);
            free(res);
        }
    return;
}
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
IMPLEMENT_LHASH_DOALL_ARG_FN(t_old, TABNODE, ALL_ARG)
#else
#define t_old t_old_doall_arg
IMPLEMENT_LHASH_DOALL_ARG_FN(t_old, TABNODE *, ALL_ARG *)
#endif

/*
 * Expire all old nodes
 */
static void
t_expire(LHASH_OF(TABNODE) *const tab, const time_t lim)
{
    ALL_ARG a;
    int down_load;

    a.tab = tab;
    a.lim = lim;
    down_load = CHECKED_LHASH_OF(TABNODE, tab)->down_load;
    CHECKED_LHASH_OF(TABNODE, tab)->down_load = 0;
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
    LHM_lh_doall_arg(TABNODE, tab, LHASH_DOALL_ARG_FN(t_old), ALL_ARG, &a);
#else
    lh_doall_arg(tab, LHASH_DOALL_ARG_FN(t_old), &a);
#endif
    CHECKED_LHASH_OF(TABNODE, tab)->down_load = down_load;
    return;
}

static void
t_cont_doall_arg(TABNODE *t, ALL_ARG *arg)
{
    TABNODE *res;

    if(memcmp(t->content, arg->content, arg->cont_len) == 0)
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
        if((res = LHM_lh_delete(TABNODE, arg->tab, t)) != NULL) {
#else
        if((res = lh_delete(arg->tab, t)) != NULL) {
#endif
            free(res->key);
            free(res->content);
            free(res);
        }
    return;
}
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
IMPLEMENT_LHASH_DOALL_ARG_FN(t_cont, TABNODE, ALL_ARG)
#else
#define t_cont t_cont_doall_arg
IMPLEMENT_LHASH_DOALL_ARG_FN(t_cont, TABNODE *, ALL_ARG *)
#endif

/*
 * Remove all nodes with the given content
 */
static void
t_clean(LHASH_OF(TABNODE) *const tab, void *const content, const size_t cont_len)
{
    ALL_ARG a;
    int down_load;

    a.tab = tab;
    a.content = content;
    a.cont_len = cont_len;
    down_load = CHECKED_LHASH_OF(TABNODE, tab)->down_load;
    CHECKED_LHASH_OF(TABNODE, tab)->down_load = 0;
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
    LHM_lh_doall_arg(TABNODE, tab, LHASH_DOALL_ARG_FN(t_cont), ALL_ARG, &a);
#else
    lh_doall_arg(tab, LHASH_DOALL_ARG_FN(t_cont), &a);
#endif
    CHECKED_LHASH_OF(TABNODE, tab)->down_load = down_load;
    return;
}

/*
 * Log an error to the syslog or to stderr
 */
#ifdef  HAVE_STDARG_H
void
logmsg(const int priority, const char *fmt, ...)
{
    char    buf[MAXBUF + 1];
    va_list ap;
    struct tm   *t_now, t_res;

    buf[MAXBUF] = '\0';
    va_start(ap, fmt);
    vsnprintf(buf, MAXBUF, fmt, ap);
    va_end(ap);
    if(log_facility == -1) {
        fprintf((priority == LOG_INFO || priority == LOG_DEBUG)? stdout: stderr, "%s\n", buf);
    } else {
        if(print_log)
            printf("%s\n", buf);
        else
            syslog(log_facility | priority, "%s", buf);
    }
    return;
}
#else
void
logmsg(const int priority, const char *fmt, va_alist)
va_dcl
{
    char    buf[MAXBUF + 1];
    va_list ap;
    struct tm   *t_now, t_res;

    buf[MAXBUF] = '\0';
    va_start(ap);
    vsnprintf(buf, MAXBUF, fmt, ap);
    va_end(ap);
    if(log_facility == -1) {
        fprintf((priority == LOG_INFO || priority == LOG_DEBUG)? stdout: stderr, "%s\n", buf);
    } else {
        if(print_log)
            printf("%s\n", buf);
        else
            syslog(log_facility | priority, "%s", buf);
    }
    return;
}
#endif

/*
 * Translate inet/inet6 address/port into a string
 */
void
addr2str(char *const res, const int res_len, const struct addrinfo *addr, const int no_port)
{
    char    buf[MAXBUF];
    int     port;
    void    *src;

    memset(res, 0, res_len);
#ifdef  HAVE_INET_NTOP
    switch(addr->ai_family) {
    case AF_INET:
        src = (void *)&((struct sockaddr_in *)addr->ai_addr)->sin_addr.s_addr;
        port = ntohs(((struct sockaddr_in *)addr->ai_addr)->sin_port);
        if(inet_ntop(AF_INET, src, buf, MAXBUF - 1) == NULL)
            strncpy(buf, "(UNKNOWN)", MAXBUF - 1);
        break;
    case AF_INET6:
        src = (void *)&((struct sockaddr_in6 *)addr->ai_addr)->sin6_addr.s6_addr;
        port = ntohs(((struct sockaddr_in6 *)addr->ai_addr)->sin6_port);
        if(inet_ntop(AF_INET6, src, buf, MAXBUF - 1) == NULL)
            strncpy(buf, "(UNKNOWN)", MAXBUF - 1);
        break;
    case AF_UNIX:
        strncpy(buf, (char *)addr->ai_addr, MAXBUF - 1);
        port = 0;
        break;
    default:
        strncpy(buf, "(UNKNOWN)", MAXBUF - 1);
        port = 0;
        break;
    }
    if(no_port)
        snprintf(res, res_len, "%s", buf);
    else
        snprintf(res, res_len, "%s:%d", buf, port);
#else
#error "Pound needs inet_ntop()"
#endif
    return;
}

/*
 * Parse a URL, possibly decoding hexadecimal-encoded characters
 */
int
cpURL(char *res, char *src, int len)
{
    int     state;
    char    *kp_res;

    for(kp_res = res, state = 0; len > 0; len--)
        switch(state) {
        case 1:
            if(*src >= '0' && *src <= '9') {
                *res = *src++ - '0';
                state = 2;
            } else if(*src >= 'A' && *src <= 'F') {
                *res = *src++ - 'A' + 10;
                state = 2;
            } else if(*src >= 'a' && *src <= 'f') {
                *res = *src++ - 'a' + 10;
                state = 2;
            } else {
                *res++ = '%';
                *res++ = *src++;
                state = 0;
            }
            break;
        case 2:
            if(*src >= '0' && *src <= '9') {
                *res = *res * 16 + *src++ - '0';
                res++;
                state = 0;
            } else if(*src >= 'A' && *src <= 'F') {
                *res = *res * 16 + *src++ - 'A' + 10;
                res++;
                state = 0;
            } else if(*src >= 'a' && *src <= 'f') {
                *res = *res * 16 + *src++ - 'a' + 10;
                res++;
                state = 0;
            } else {
                *res++ = '%';
                *res++ = *(src - 1);
                *res++ = *src++;
                state = 0;
            }
            break;
        default:
            if(*src != '%')
                *res++ = *src++;
            else {
                src++;
                state = 1;
            }
            break;
        }
    if(state > 0)
        *res++ = '%';
    if(state > 1)
        *res++ = *(src - 1);
    *res = '\0';
    return res - kp_res;
}

/*
 * Parse a header
 * return a code and possibly content in the arg
 */
int
check_header(const char *header, char *const content)
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
        { "Content-location",   16, HEADER_CONTLOCATION },
        { "Host",               4,  HEADER_HOST },
        { "Referer",            7,  HEADER_REFERER },
        { "User-agent",         10, HEADER_USER_AGENT },
        { "Destination",        11, HEADER_DESTINATION },
        { "Expect",             6,  HEADER_EXPECT },
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

static int
match_service(const SERVICE *svc, const char *request, char **const headers)
{
    MATCHER *m;
    int     i, found;

    /* check for request */
    for(m = svc->url; m; m = m->next)
        if(regexec(&m->pat, request, 0, NULL, 0))
            return 0;

    /* check for required headers */
    for(m = svc->req_head; m; m = m->next) {
        for(found = i = 0; i < (MAXHEADERS - 1) && !found; i++)
            if(headers[i] && !regexec(&m->pat, headers[i], 0, NULL, 0))
                found = 1;
        if(!found)
            return 0;
    }

    /* check for forbidden headers */
    for(m = svc->deny_head; m; m = m->next) {
        for(found = i = 0; i < (MAXHEADERS - 1) && !found; i++)
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
get_service(const LISTENER *lstn, const char *request, char **const headers)
{
    SERVICE *svc;

    for(svc = lstn->services; svc; svc = svc->next) {
        if(svc->disabled)
            continue;
        if(match_service(svc, request, headers))
            return svc;
    }

    /* try global services */
    for(svc = services; svc; svc = svc->next) {
        if(svc->disabled)
            continue;
        if(match_service(svc, request, headers))
            return svc;
    }

    /* nothing matched */
    return NULL;
}

/*
 * extract the session key for a given request
 */
static int
get_REQUEST(char *res, const SERVICE *svc, const char *request)
{
    int         n, s;
    regmatch_t  matches[4];

    if(regexec(&svc->sess_start, request, 4, matches, 0)) {
        res[0] = '\0';
        return 0;
    }
    s = matches[0].rm_eo;
    if(regexec(&svc->sess_pat, request + s, 4, matches, 0)) {
        res[0] = '\0';
        return 0;
    }
    if((n = matches[1].rm_eo - matches[1].rm_so) > KEY_SIZE)
        n = KEY_SIZE;
    strncpy(res, request + s + matches[1].rm_so, n);
    res[n] = '\0';
    return 1;
}

static int
get_HEADERS(char *res, const SERVICE *svc, char **const headers)
{
    int         i, n, s;
    regmatch_t  matches[4];

    /* this will match SESS_COOKIE, SESS_HEADER and SESS_BASIC */
    res[0] = '\0';
    for(i = 0; i < (MAXHEADERS - 1); i++) {
        if(headers[i] == NULL)
            continue;
        if(regexec(&svc->sess_start, headers[i], 4, matches, 0))
            continue;
        s = matches[0].rm_eo;
        if(regexec(&svc->sess_pat, headers[i] + s, 4, matches, 0))
            continue;
        if((n = matches[1].rm_eo - matches[1].rm_so) > KEY_SIZE)
            n = KEY_SIZE;
        strncpy(res, headers[i] + s + matches[1].rm_so, n);
        res[n] = '\0';
    }
    return res[0] != '\0';
}

/*
 * Pick a random back-end from a candidate list
 */
static BACKEND *
rand_backend(BACKEND *be, int pri)
{
    while(be) {
        if(!be->alive || be->disabled) {
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
 * return a back-end based on a fixed hash value
 * this is used for session_ttl < 0
 * 
 * WARNING: the function may return different back-ends
 * if the target back-end is disabled or not alive
 */
static BACKEND *
hash_backend(BACKEND *be, int abs_pri, char *key)
{
    unsigned long   hv;
    BACKEND         *res, *tb;
    int             pri;

    hv = 2166136261;
    while(*key)
        hv = ((hv ^ *key++) * 16777619) & 0xFFFFFFFF;
    pri = hv % abs_pri;
    for(tb = be; tb; tb = tb->next)
        if((pri -= tb->priority) < 0)
            break;
    if(!tb)
        /* should NEVER happen */
        return NULL;
    for(res = tb; !res->alive || res->disabled; ) {
        res = res->next;
        if(res == NULL)
            res = be;
        if(res == tb)
            /* NO back-end available */
            return NULL;
    }
    return res;
}

/*
 * Find the right back-end for a request
 */
BACKEND *
get_backend(SERVICE *const svc, const struct addrinfo *from_host, const char *request, char **const headers)
{
    BACKEND     *res;
    char        key[KEY_SIZE + 1];
    int         ret_val, no_be;
    void        *vp;

    if(ret_val = pthread_mutex_lock(&svc->mut))
        logmsg(LOG_WARNING, "get_backend() lock: %s", strerror(ret_val));

    no_be = (svc->tot_pri <= 0);

    switch(svc->sess_type) {
    case SESS_NONE:
        /* choose one back-end randomly */
        res = no_be? svc->emergency: rand_backend(svc->backends, random() % svc->tot_pri);
        break;
    case SESS_IP:
        addr2str(key, KEY_SIZE, from_host, 1);
        if(svc->sess_ttl < 0)
            res = no_be? svc->emergency: hash_backend(svc->backends, svc->abs_pri, key);
        else if((vp = t_find(svc->sessions, key)) == NULL) {
            if(no_be)
                res = svc->emergency;
            else {
                /* no session yet - create one */
                res = rand_backend(svc->backends, random() % svc->tot_pri);
                t_add(svc->sessions, key, &res, sizeof(res));
            }
        } else
            memcpy(&res, vp, sizeof(res));
        break;
    case SESS_URL:
    case SESS_PARM:
        if(get_REQUEST(key, svc, request)) {
            if(svc->sess_ttl < 0)
                res = no_be? svc->emergency: hash_backend(svc->backends, svc->abs_pri, key);
            else if((vp = t_find(svc->sessions, key)) == NULL) {
                if(no_be)
                    res = svc->emergency;
                else {
                    /* no session yet - create one */
                    res = rand_backend(svc->backends, random() % svc->tot_pri);
                    t_add(svc->sessions, key, &res, sizeof(res));
                }
            } else
                memcpy(&res, vp, sizeof(res));
        } else {
            res = no_be? svc->emergency: rand_backend(svc->backends, random() % svc->tot_pri);
        }
        break;
    default:
        /* this works for SESS_BASIC, SESS_HEADER and SESS_COOKIE */
        if(get_HEADERS(key, svc, headers)) {
            if(svc->sess_ttl < 0)
                res = no_be? svc->emergency: hash_backend(svc->backends, svc->abs_pri, key);
            else if((vp = t_find(svc->sessions, key)) == NULL) {
                if(no_be)
                    res = svc->emergency;
                else {
                    /* no session yet - create one */
                    res = rand_backend(svc->backends, random() % svc->tot_pri);
                    t_add(svc->sessions, key, &res, sizeof(res));
                }
            } else
                memcpy(&res, vp, sizeof(res));
        } else {
            res = no_be? svc->emergency: rand_backend(svc->backends, random() % svc->tot_pri);
        }
        break;
    }
    if(ret_val = pthread_mutex_unlock(&svc->mut))
        logmsg(LOG_WARNING, "get_backend() unlock: %s", strerror(ret_val));

    return res;
}

/*
 * (for cookies/header only) possibly create session based on response headers
 */
void
upd_session(SERVICE *const svc, char **const headers, BACKEND *const be)
{
    char            key[KEY_SIZE + 1];
    int             ret_val;

    if(svc->sess_type != SESS_HEADER && svc->sess_type != SESS_COOKIE)
        return;
    if(ret_val = pthread_mutex_lock(&svc->mut))
        logmsg(LOG_WARNING, "upd_session() lock: %s", strerror(ret_val));
    if(get_HEADERS(key, svc, headers))
        if(t_find(svc->sessions, key) == NULL)
            t_add(svc->sessions, key, &be, sizeof(be));
    if(ret_val = pthread_mutex_unlock(&svc->mut))
        logmsg(LOG_WARNING, "upd_session() unlock: %s", strerror(ret_val));
    return;
}

/*
 * mark a backend host as dead/disabled; remove its sessions if necessary
 *  disable_only == 1:  mark as disabled
 *  disable_only == 0:  mark as dead, remove sessions
 *  disable_only == -1:  mark as enabled
 */
void
kill_be(SERVICE *const svc, const BACKEND *be, const int disable_mode)
{
    BACKEND *b;
    int     ret_val;
    char    buf[MAXBUF];

    if(ret_val = pthread_mutex_lock(&svc->mut))
        logmsg(LOG_WARNING, "kill_be() lock: %s", strerror(ret_val));
    svc->tot_pri = 0;
    for(b = svc->backends; b; b = b->next) {
        if(b == be)
            switch(disable_mode) {
            case BE_DISABLE:
                b->disabled = 1;
                str_be(buf, MAXBUF - 1, b);
                logmsg(LOG_NOTICE, "(%lx) BackEnd %s disabled", pthread_self(), buf);
                break;
            case BE_KILL:
                b->alive = 0;
                str_be(buf, MAXBUF - 1, b);
                logmsg(LOG_NOTICE, "(%lx) BackEnd %s dead (killed)", pthread_self(), buf);
                t_clean(svc->sessions, &be, sizeof(be));
                break;
            case BE_ENABLE:
                str_be(buf, MAXBUF - 1, b);
                logmsg(LOG_NOTICE, "(%lx) BackEnd %s enabled", pthread_self(), buf);
                b->disabled = 0;
                break;
            default:
                logmsg(LOG_WARNING, "kill_be(): unknown mode %d", disable_mode);
                break;
            }
        if(b->alive && !b->disabled)
            svc->tot_pri += b->priority;
    }
    if(ret_val = pthread_mutex_unlock(&svc->mut))
        logmsg(LOG_WARNING, "kill_be() unlock: %s", strerror(ret_val));
    return;
}

/*
 * Search for a host name, return the addrinfo for it
 */
int
get_host(char *const name, struct addrinfo *res, int ai_family)
{
    struct addrinfo *chain, *ap;
    struct addrinfo hints;
    int             ret_val;

#ifdef  HAVE_INET_NTOP
    memset (&hints, 0, sizeof(hints));
    hints.ai_family = ai_family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    if((ret_val = getaddrinfo(name, NULL, &hints, &chain)) == 0) {
#ifdef _AIX
        ap = chain;
#else
        for(ap = chain; ap != NULL; ap = ap->ai_next)
            if(ap->ai_socktype == SOCK_STREAM)
                break;
#endif
        if(ap == NULL) {
            freeaddrinfo(chain);
            return EAI_NONAME;
        }
        *res = *ap;
        if((res->ai_addr = (struct sockaddr *)malloc(ap->ai_addrlen)) == NULL) {
            freeaddrinfo(chain);
            return EAI_MEMORY;
        }
        memcpy(res->ai_addr, ap->ai_addr, ap->ai_addrlen);
        freeaddrinfo(chain);
    }
#else
#error  "Pound requires getaddrinfo()"
#endif
    return ret_val;
}

/*
 * Find if a redirect needs rewriting
 * In general we have two possibilities that require it:
 * (1) if the redirect was done to the correct location with the wrong port
 * (2) if the redirect was done to the back-end rather than the listener
 */
int
need_rewrite(const int rewr_loc, char *const location, char *const path, const char *v_host, const LISTENER *lstn, const BACKEND *be)
{
    struct addrinfo         addr;
    struct sockaddr_in      in_addr, be_addr;
    struct sockaddr_in6     in6_addr, be6_addr;
    regmatch_t              matches[4];
    char                    *proto, *host, *port, *cp, buf[MAXBUF];

    /* check if rewriting is required at all */
    if(rewr_loc == 0)
        return 0;

    /* applies only to INET/INET6 back-ends */
    if(be->addr.ai_family != AF_INET && be->addr.ai_family != AF_INET6)
        return 0;

    /* split the location into its fields */
    if(regexec(&LOCATION, location, 4, matches, 0))
        return 0;
    proto = location + matches[1].rm_so;
    host = location + matches[2].rm_so;
    if(location[matches[3].rm_so] == '/')
        matches[3].rm_so++;
    /* path is guaranteed to be large enough */
    strcpy(path, location + matches[3].rm_so);
    location[matches[1].rm_eo] = location[matches[2].rm_eo] = '\0';
    if((port = strchr(host, ':')) != NULL)
        *port++ = '\0';

    /*
     * Check if the location has the same address as the listener or the back-end
     */
    memset(&addr, 0, sizeof(addr));
    if(get_host(host, &addr, be->addr.ai_family))
        return 0;

    /*
     * compare the back-end
     */
    if(addr.ai_family != be->addr.ai_family) {
        free(addr.ai_addr);
        return 0;
    }
    if(addr.ai_family == AF_INET) {
        memcpy(&in_addr, addr.ai_addr, sizeof(in_addr));
        memcpy(&be_addr, be->addr.ai_addr, sizeof(be_addr));
        if(port)
            in_addr.sin_port = (in_port_t)htons(atoi(port));
        else if(!strcasecmp(proto, "https"))
            in_addr.sin_port = (in_port_t)htons(443);
        else
            in_addr.sin_port = (in_port_t)htons(80);
        /*
         * check if the Location points to the back-end
         */
        if(memcmp(&be_addr.sin_addr.s_addr, &in_addr.sin_addr.s_addr, sizeof(in_addr.sin_addr.s_addr)) == 0
        && memcmp(&be_addr.sin_port, &in_addr.sin_port, sizeof(in_addr.sin_port)) == 0) {
            free(addr.ai_addr);
            return 1;
        }
    } else /* AF_INET6 */ {
        memcpy(&in6_addr, addr.ai_addr, sizeof(in6_addr));
        memcpy(&be6_addr, be->addr.ai_addr, sizeof(be6_addr));
        if(port)
            in6_addr.sin6_port = (in_port_t)htons(atoi(port));
        else if(!strcasecmp(proto, "https"))
            in6_addr.sin6_port = (in_port_t)htons(443);
        else
            in6_addr.sin6_port = (in_port_t)htons(80);
        /*
         * check if the Location points to the back-end
         */
        if(memcmp(&be6_addr.sin6_addr.s6_addr, &in6_addr.sin6_addr.s6_addr, sizeof(in6_addr.sin6_addr.s6_addr)) == 0
        && memcmp(&be6_addr.sin6_port, &in6_addr.sin6_port, sizeof(in6_addr.sin6_port)) == 0) {
            free(addr.ai_addr);
            return 1;
        }
    }

    /*
     * compare the listener
     */
    if(rewr_loc != 1 || addr.ai_family != lstn->addr.ai_family) {
        free(addr.ai_addr);
        return 0;
    }
    memset(buf, '\0', MAXBUF);
    strncpy(buf, v_host, MAXBUF - 1);
    if((cp = strchr(buf, ':')) != NULL)
        *cp = '\0';
    if(addr.ai_family == AF_INET) {
        memcpy(&be_addr, lstn->addr.ai_addr, sizeof(be_addr));
        /*
         * check if the Location points to the Listener but with the wrong port or protocol
         */
        if((memcmp(&be_addr.sin_addr.s_addr, &in_addr.sin_addr.s_addr, sizeof(in_addr.sin_addr.s_addr)) == 0
          || strcasecmp(host, buf) == 0)
        && (memcmp(&be_addr.sin_port, &in_addr.sin_port, sizeof(in_addr.sin_port)) != 0
            || strcasecmp(proto, lstn->ctx? "http": "https"))) {
            free(addr.ai_addr);
            return 1;
        }
    } else {
        memcpy(&be6_addr, lstn->addr.ai_addr, sizeof(be6_addr));
        /*
         * check if the Location points to the Listener but with the wrong port or protocol
         */
        if((memcmp(&be6_addr.sin6_addr.s6_addr, &in6_addr.sin6_addr.s6_addr, sizeof(in6_addr.sin6_addr.s6_addr)) == 0
          || strcasecmp(host, buf) == 0)
        && (memcmp(&be6_addr.sin6_port, &in6_addr.sin6_port, sizeof(in6_addr.sin6_port)) != 0
            || strcasecmp(proto, lstn->ctx? "http": "https"))) {
            free(addr.ai_addr);
            return 1;
        }
    }

    free(addr.ai_addr);
    return 0;
}

/*
 * Non-blocking connect(). Does the same as connect(2) but ensures
 * it will time-out after a much shorter time period SERVER_TO
 */
int
connect_nb(const int sockfd, const struct addrinfo *serv_addr, const int to)
{
    int             flags, res, error;
    socklen_t       len;
    struct pollfd   p;

    if((flags = fcntl(sockfd, F_GETFL, 0)) < 0) {
        logmsg(LOG_WARNING, "(%lx) connect_nb: fcntl GETFL failed: %s", pthread_self(), strerror(errno));
        return -1;
    }
    if(fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        logmsg(LOG_WARNING, "(%lx) connect_nb: fcntl SETFL failed: %s", pthread_self(), strerror(errno));
        return -1;
    }

    error = 0;
    if((res = connect(sockfd, serv_addr->ai_addr, serv_addr->ai_addrlen)) < 0)
        if(errno != EINPROGRESS) {
            logmsg(LOG_WARNING, "(%lx) connect_nb: connect failed: %s", pthread_self(), strerror(errno));
            return (-1);
        }

    if(res == 0) {
        /* connect completed immediately (usually localhost) */
        if(fcntl(sockfd, F_SETFL, flags) < 0) {
            logmsg(LOG_WARNING, "(%lx) connect_nb: fcntl reSETFL failed: %s", pthread_self(), strerror(errno));
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
            logmsg(LOG_WARNING, "(%lx) connect_nb: poll timed out", pthread_self());
            errno = ETIMEDOUT;
        } else
            logmsg(LOG_WARNING, "(%lx) connect_nb: poll failed: %s", pthread_self(), strerror(errno));
        return -1;
    }

    /* socket is writeable == operation completed */
    len = sizeof(error);
    if(getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        logmsg(LOG_WARNING, "(%lx) connect_nb: getsockopt failed: %s", pthread_self(), strerror(errno));
        return -1;
    }

    /* restore file status flags */
    if(fcntl(sockfd, F_SETFL, flags) < 0) {
        logmsg(LOG_WARNING, "(%lx) connect_nb: fcntl reSETFL failed: %s", pthread_self(), strerror(errno));
        return -1;
    }

    if(error) {
        /* getsockopt() shows an error */
        errno = error;
        logmsg(LOG_WARNING, "(%lx) connect_nb: error after getsockopt: %s", pthread_self(), strerror(errno));
        return -1;
    }

    /* really connected */
    return 0;
}

/*
 * Check if dead hosts returned to life;
 * runs every alive seconds
 */
static void
do_resurect(void)
{
    LISTENER    *lstn;
    SERVICE     *svc;
    BACKEND     *be;
    struct      addrinfo    z_addr, *addr;
    int         sock, modified;
    char        buf[MAXBUF];
    int         ret_val;

    /* check hosts still alive - HAport */
    memset(&z_addr, 0, sizeof(z_addr));
    for(lstn = listeners; lstn; lstn = lstn->next)
    for(svc = lstn->services; svc; svc = svc->next)
    for(be = svc->backends; be; be = be->next) {
        if(be->be_type)
            continue;
        if(!be->alive)
            /* already dead */
            continue;
        if(memcmp(&(be->ha_addr), &z_addr, sizeof(z_addr)) == 0)
            /* no HA port */
            continue;
        /* try connecting */
        switch(be->ha_addr.ai_family) {
        case AF_INET:
            if((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
                continue;
            break;
        case AF_INET6:
            if((sock = socket(PF_INET6, SOCK_STREAM, 0)) < 0)
                continue;
            break;
        case AF_UNIX:
            if((sock = socket(PF_UNIX, SOCK_STREAM, 0)) < 0)
                continue;
            break;
        default:
            continue;
        }
        if(connect_nb(sock, &be->ha_addr, be->conn_to) != 0) {
            kill_be(svc, be, BE_KILL);
            str_be(buf, MAXBUF - 1, be);
            logmsg(LOG_NOTICE, "BackEnd %s is dead (HA)", buf);
        }
        shutdown(sock, 2);
        close(sock);
    }

    for(svc = services; svc; svc = svc->next)
    for(be = svc->backends; be; be = be->next) {
        if(be->be_type)
            continue;
        if(!be->alive)
            /* already dead */
            continue;
        if(memcmp(&(be->ha_addr), &z_addr, sizeof(z_addr)) == 0)
            /* no HA port */
            continue;
        /* try connecting */
        switch(be->ha_addr.ai_family) {
        case AF_INET:
            if((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
                continue;
            break;
        case AF_INET6:
            if((sock = socket(PF_INET6, SOCK_STREAM, 0)) < 0)
                continue;
            break;
        case AF_UNIX:
            if((sock = socket(PF_UNIX, SOCK_STREAM, 0)) < 0)
                continue;
            break;
        default:
            continue;
        }
        if(connect_nb(sock, &be->ha_addr, be->conn_to) != 0) {
            kill_be(svc, be, BE_KILL);
            str_be(buf, MAXBUF - 1, be);
            logmsg(LOG_NOTICE, "BackEnd %s is dead (HA)", buf);
        }
        shutdown(sock, 2);
        close(sock);
    }

    /* check hosts alive again */
    for(lstn = listeners; lstn; lstn = lstn->next)
    for(svc = lstn->services; svc; svc = svc->next) {
        for(modified = 0, be = svc->backends; be; be = be->next) {
            be->resurrect = 0;
            if(be->be_type)
                continue;
            if(be->alive)
                continue;
            if(memcmp(&(be->ha_addr), &z_addr, sizeof(z_addr)) == 0) {
                switch(be->addr.ai_family) {
                case AF_INET:
                    if((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
                        continue;
                    break;
                case AF_INET6:
                    if((sock = socket(PF_INET6, SOCK_STREAM, 0)) < 0)
                        continue;
                    break;
                case AF_UNIX:
                    if((sock = socket(PF_UNIX, SOCK_STREAM, 0)) < 0)
                        continue;
                    break;
                default:
                    continue;
                }
                addr = &be->addr;
            } else {
                switch(be->ha_addr.ai_family) {
                case AF_INET:
                    if((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
                        continue;
                    break;
                case AF_INET6:
                    if((sock = socket(PF_INET6, SOCK_STREAM, 0)) < 0)
                        continue;
                    break;
                case AF_UNIX:
                    if((sock = socket(PF_UNIX, SOCK_STREAM, 0)) < 0)
                        continue;
                    break;
                default:
                    continue;
                }
                addr = &be->ha_addr;
            }
            if(connect_nb(sock, addr, be->conn_to) == 0) {
                be->resurrect = 1;
                modified = 1;
            }
            shutdown(sock, 2);
            close(sock);
        }
        if(modified) {
            if(ret_val = pthread_mutex_lock(&svc->mut))
                logmsg(LOG_WARNING, "do_resurect() lock: %s", strerror(ret_val));
            svc->tot_pri = 0;
            for(be = svc->backends; be; be = be->next) {
                if(be->resurrect) {
                    be->alive = 1;
                    str_be(buf, MAXBUF - 1, be);
                    logmsg(LOG_NOTICE, "BackEnd %s resurrect", buf);
                }
                if(be->alive && !be->disabled)
                    svc->tot_pri += be->priority;
            }
            if(ret_val = pthread_mutex_unlock(&svc->mut))
                logmsg(LOG_WARNING, "do_resurect() unlock: %s", strerror(ret_val));
        }
    }

    for(svc = services; svc; svc = svc->next) {
        for(modified = 0, be = svc->backends; be; be = be->next) {
            be->resurrect = 0;
            if(be->be_type)
                continue;
            if(be->alive)
                continue;
            if(memcmp(&(be->ha_addr), &z_addr, sizeof(z_addr)) == 0) {
                switch(be->addr.ai_family) {
                case AF_INET:
                    if((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
                        continue;
                    break;
                case AF_INET6:
                    if((sock = socket(PF_INET6, SOCK_STREAM, 0)) < 0)
                        continue;
                    break;
                case AF_UNIX:
                    if((sock = socket(PF_UNIX, SOCK_STREAM, 0)) < 0)
                        continue;
                    break;
                default:
                    continue;
                }
                addr = &be->addr;
            } else {
                switch(be->ha_addr.ai_family) {
                case AF_INET:
                    if((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
                        continue;
                    break;
                case AF_INET6:
                    if((sock = socket(PF_INET6, SOCK_STREAM, 0)) < 0)
                        continue;
                    break;
                case AF_UNIX:
                    if((sock = socket(PF_UNIX, SOCK_STREAM, 0)) < 0)
                        continue;
                    break;
                default:
                    continue;
                }
                addr = &be->ha_addr;
            }
            if(connect_nb(sock, addr, be->conn_to) == 0) {
                be->resurrect = 1;
                modified = 1;
            }
            shutdown(sock, 2);
            close(sock);
        }
        if(modified) {
            if(ret_val = pthread_mutex_lock(&svc->mut))
                logmsg(LOG_WARNING, "do_resurect() lock: %s", strerror(ret_val));
            svc->tot_pri = 0;
            for(be = svc->backends; be; be = be->next) {
                if(be->resurrect) {
                    be->alive = 1;
                    str_be(buf, MAXBUF - 1, be);
                    logmsg(LOG_NOTICE, "BackEnd %s resurrect", buf);
                }
                if(be->alive && !be->disabled)
                    svc->tot_pri += be->priority;
            }
            if(ret_val = pthread_mutex_unlock(&svc->mut))
                logmsg(LOG_WARNING, "do_resurect() unlock: %s", strerror(ret_val));
        }
    }
    
    return;
}

/*
 * Remove expired sessions
 * runs every EXPIRE_TO seconds
 */
static void
do_expire(void)
{
    LISTENER    *lstn;
    SERVICE     *svc;
    time_t      cur_time;
    int         ret_val;

    /* remove stale sessions */
    cur_time = time(NULL);

    for(lstn = listeners; lstn; lstn = lstn->next)
    for(svc = lstn->services; svc; svc = svc->next)
        if(svc->sess_type != SESS_NONE) {
            if(ret_val = pthread_mutex_lock(&svc->mut)) {
                logmsg(LOG_WARNING, "do_expire() lock: %s", strerror(ret_val));
                continue;
            }
            t_expire(svc->sessions, cur_time - svc->sess_ttl);
            if(ret_val = pthread_mutex_unlock(&svc->mut))
                logmsg(LOG_WARNING, "do_expire() unlock: %s", strerror(ret_val));
        }

    for(svc = services; svc; svc = svc->next)
        if(svc->sess_type != SESS_NONE) {
            if(ret_val = pthread_mutex_lock(&svc->mut)) {
                logmsg(LOG_WARNING, "do_expire() lock: %s", strerror(ret_val));
                continue;
            }
            t_expire(svc->sessions, cur_time - svc->sess_ttl);
            if(ret_val = pthread_mutex_unlock(&svc->mut))
                logmsg(LOG_WARNING, "do_expire() unlock: %s", strerror(ret_val));
        }

    return;
}

static pthread_mutex_t  RSA_mut;                    /* mutex for RSA keygen */
static RSA              *RSA512_keys[N_RSA_KEYS];   /* ephemeral RSA keys */
static RSA              *RSA1024_keys[N_RSA_KEYS];  /* ephemeral RSA keys */

/*
 * return a pre-generated RSA key
 */
RSA *
RSA_tmp_callback(/* not used */SSL *ssl, /* not used */int is_export, int keylength)
{
    RSA *res;
    int ret_val;

    if(ret_val = pthread_mutex_lock(&RSA_mut))
        logmsg(LOG_WARNING, "RSA_tmp_callback() lock: %s", strerror(ret_val));
    res = (keylength <= 512)? RSA512_keys[rand() % N_RSA_KEYS]: RSA1024_keys[rand() % N_RSA_KEYS];
    if(ret_val = pthread_mutex_unlock(&RSA_mut))
        logmsg(LOG_WARNING, "RSA_tmp_callback() unlock: %s", strerror(ret_val));
    return res;
}

/*
 * Periodically regenerate ephemeral RSA keys
 * runs every T_RSA_KEYS seconds
 */
static void
do_RSAgen(void)
{
    int n, ret_val;
    RSA *t_RSA512_keys[N_RSA_KEYS];
    RSA *t_RSA1024_keys[N_RSA_KEYS];

    for(n = 0; n < N_RSA_KEYS; n++) {
        t_RSA512_keys[n] = RSA_generate_key(512, RSA_F4, NULL, NULL);
        t_RSA1024_keys[n] = RSA_generate_key(1024, RSA_F4, NULL, NULL);
    }
    if(ret_val = pthread_mutex_lock(&RSA_mut))
        logmsg(LOG_WARNING, "thr_RSAgen() lock: %s", strerror(ret_val));
    for(n = 0; n < N_RSA_KEYS; n++) {
        RSA_free(RSA512_keys[n]);
        RSA512_keys[n] = t_RSA512_keys[n];
        RSA_free(RSA1024_keys[n]);
        RSA1024_keys[n] = t_RSA1024_keys[n];
    }
    if(ret_val = pthread_mutex_unlock(&RSA_mut))
        logmsg(LOG_WARNING, "thr_RSAgen() unlock: %s", strerror(ret_val));
    return;
}

#include    "dh512.h"

#if DH_LEN == 1024
#include    "dh1024.h"
static DH   *DH512_params, *DH1024_params;

DH *
DH_tmp_callback(/* not used */SSL *s, /* not used */int is_export, int keylength)
{
    return keylength == 512? DH512_params: DH1024_params;
}
#else
#include    "dh2048.h"
static DH   *DH512_params, *DH2048_params;

DH *
DH_tmp_callback(/* not used */SSL *s, /* not used */int is_export, int keylength)
{
    return keylength == 512? DH512_params: DH2048_params;
}
#endif

static time_t   last_RSA, last_alive, last_expire;

/*
 * initialise the timer functions:
 *  - RSA_mut and keys
 */
void
init_timer(void)
{
    int n;

    last_RSA = last_alive = last_expire = time(NULL);

    /*
     * Pre-generate ephemeral RSA keys
     */
    for(n = 0; n < N_RSA_KEYS; n++) {
        if((RSA512_keys[n] = RSA_generate_key(512, RSA_F4, NULL, NULL)) == NULL) {
            logmsg(LOG_WARNING,"RSA_generate(%d, 512) failed", n);
            return;
        }
        if((RSA1024_keys[n] = RSA_generate_key(1024, RSA_F4, NULL, NULL)) == NULL) {
            logmsg(LOG_WARNING,"RSA_generate(%d, 1024) failed", n);
            return;
        }
    }
    /* pthread_mutex_init() always returns 0 */
    pthread_mutex_init(&RSA_mut, NULL);

    DH512_params = get_dh512();
#if DH_LEN == 1024
    DH1024_params = get_dh1024();
#else
    DH2048_params = get_dh2048();
#endif

    return;
}

/*
 * run timed functions:
 *  - RSAgen every T_RSA_KEYS seconds
 *  - resurect every alive_to seconds
 *  - expire every EXPIRE_TO seconds
 */
void *
thr_timer(void *arg)
{
    time_t  last_time, cur_time;
    int     n_wait, n_remain;

    n_wait = EXPIRE_TO;
    if(n_wait > alive_to)
        n_wait = alive_to;
    if(n_wait > T_RSA_KEYS)
        n_wait = T_RSA_KEYS;
    for(last_time = time(NULL) - n_wait;;) {
        cur_time = time(NULL);
        if((n_remain = n_wait - (cur_time - last_time)) > 0)
            sleep(n_remain);
        last_time = time(NULL);
        if((last_time - last_RSA) >= T_RSA_KEYS) {
            last_RSA = time(NULL);
            do_RSAgen();
        }
        if((last_time - last_alive) >= alive_to) {
            last_alive = time(NULL);
            do_resurect();
        }
        if((last_time - last_expire) >= EXPIRE_TO) {
            last_expire = time(NULL);
            do_expire();
        }
    }
}

typedef struct  {
    int     control_sock;
    BACKEND *backends;
}   DUMP_ARG;

static void
t_dump_doall_arg(TABNODE *t, DUMP_ARG *arg)
{
    BACKEND     *be, *bep;
    int         n_be, sz;

    memcpy(&bep, t->content, sizeof(bep));
    for(n_be = 0, be = arg->backends; be; be = be->next, n_be++)
        if(be == bep)
            break;
    if(!be)
        /* should NEVER happen */
        n_be = 0;
    (void)write(arg->control_sock, t, sizeof(TABNODE));
    (void)write(arg->control_sock, &n_be, sizeof(n_be));
    sz = strlen(t->key);
    (void)write(arg->control_sock, &sz, sizeof(sz));
    (void)write(arg->control_sock, t->key, sz);
    return;
}
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
IMPLEMENT_LHASH_DOALL_ARG_FN(t_dump, TABNODE, DUMP_ARG)
#else
#define t_dump t_dump_doall_arg
IMPLEMENT_LHASH_DOALL_ARG_FN(t_dump, TABNODE *, DUMP_ARG *)
#endif

/*
 * write sessions to the control socket
 */
static void
dump_sess(const int control_sock, LHASH_OF(TABNODE) *const sess, BACKEND *const backends)
{
    DUMP_ARG a;

    a.control_sock = control_sock;
    a.backends = backends;
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
    LHM_lh_doall_arg(TABNODE, sess, LHASH_DOALL_ARG_FN(t_dump), DUMP_ARG, &a);
#else
    lh_doall_arg(sess, LHASH_DOALL_ARG_FN(t_dump), &a);
#endif
    return;
}

/*
 * given a command, select a listener
 */
static LISTENER *
sel_lstn(const CTRL_CMD *cmd)
{
    LISTENER    *lstn;
    int         i;

    if(cmd->listener < 0)
        return NULL;
    for(i = 0, lstn = listeners; lstn && i < cmd->listener; i++, lstn = lstn->next)
        ;
    return lstn;
}

/*
 * given a command, select a service
 */
static SERVICE *
sel_svc(const CTRL_CMD *cmd)
{
    SERVICE     *svc;
    LISTENER    *lstn;
    int         i;

    if(cmd->listener < 0) {
        svc = services;
    } else {
        if((lstn = sel_lstn(cmd)) == NULL)
            return NULL;
        svc = lstn->services;
    }
    for(i = 0; svc && i < cmd->service; i++, svc = svc->next)
        ;
    return svc;
}

/*
 * given a command, select a back-end
 */
static BACKEND *
sel_be(const CTRL_CMD *cmd)
{
    BACKEND     *be;
    SERVICE     *svc;
    int         i;

    if((svc = sel_svc(cmd)) == NULL)
        return NULL;
    for(i = 0, be = svc->backends; be && i < cmd->backend; i++, be = be->next)
        ;
    return be;
}

/*
 * The controlling thread
 * listens to client requests and calls the appropriate functions
 */
void *
thr_control(void *arg)
{
    CTRL_CMD        cmd;
    struct sockaddr sa;
    int             ctl, dummy, n, ret_val;
    LISTENER        *lstn, dummy_lstn;
    SERVICE         *svc, dummy_svc;
    BACKEND         *be, dummy_be;
    TABNODE         dummy_sess;
    struct pollfd   polls;

    /* just to be safe */
    if(control_sock < 0)
        return NULL;
    memset(&dummy_lstn, 0, sizeof(dummy_lstn));
    dummy_lstn.disabled = -1;
    memset(&dummy_svc, 0, sizeof(dummy_svc));
    dummy_svc.disabled = -1;
    memset(&dummy_be, 0, sizeof(dummy_be));
    dummy_be.disabled = -1;
    memset(&dummy_sess, 0, sizeof(dummy_sess));
    dummy_sess.content = NULL;
    dummy = sizeof(sa);
    for(;;) {
        polls.fd = control_sock;
        polls.events = POLLIN | POLLPRI;
        polls.revents = 0;
        if(poll(&polls, 1, -1) < 0) {
            logmsg(LOG_WARNING, "thr_control() poll: %s", strerror(errno));
            continue;
        }
        if((ctl = accept(control_sock, &sa, (socklen_t *)&dummy)) < 0) {
            logmsg(LOG_WARNING, "thr_control() accept: %s", strerror(errno));
            continue;
        }
        if(read(ctl, &cmd, sizeof(cmd)) != sizeof(cmd)) {
            logmsg(LOG_WARNING, "thr_control() read: %s", strerror(errno));
            continue;
        }
        switch(cmd.cmd) {
        case CTRL_LST:
            /* logmsg(LOG_INFO, "thr_control() list"); */
            n = get_thr_qlen();
            (void)write(ctl, (void *)&n, sizeof(n));
            for(lstn = listeners; lstn; lstn = lstn->next) {
                (void)write(ctl, (void *)lstn, sizeof(LISTENER));
                (void)write(ctl, lstn->addr.ai_addr, lstn->addr.ai_addrlen);
                for(svc = lstn->services; svc; svc = svc->next) {
                    (void)write(ctl, (void *)svc, sizeof(SERVICE));
                    for(be = svc->backends; be; be = be->next) {
                        (void)write(ctl, (void *)be, sizeof(BACKEND));
                        (void)write(ctl, be->addr.ai_addr, be->addr.ai_addrlen);
                        if(be->ha_addr.ai_addrlen > 0)
                            (void)write(ctl, be->ha_addr.ai_addr, be->ha_addr.ai_addrlen);
                    }
                    (void)write(ctl, (void *)&dummy_be, sizeof(BACKEND));
                    if(dummy = pthread_mutex_lock(&svc->mut))
                        logmsg(LOG_WARNING, "thr_control() lock: %s", strerror(dummy));
                    else {
                        dump_sess(ctl, svc->sessions, svc->backends);
                        if(dummy = pthread_mutex_unlock(&svc->mut))
                            logmsg(LOG_WARNING, "thr_control() unlock: %s", strerror(dummy));
                    }
                    (void)write(ctl, (void *)&dummy_sess, sizeof(TABNODE));
                }
                (void)write(ctl, (void *)&dummy_svc, sizeof(SERVICE));
            }
            (void)write(ctl, (void *)&dummy_lstn, sizeof(LISTENER));
            for(svc = services; svc; svc = svc->next) {
                (void)write(ctl, (void *)svc, sizeof(SERVICE));
                for(be = svc->backends; be; be = be->next) {
                    (void)write(ctl, (void *)be, sizeof(BACKEND));
                    (void)write(ctl, be->addr.ai_addr, be->addr.ai_addrlen);
                    if(be->ha_addr.ai_addrlen > 0)
                        (void)write(ctl, be->ha_addr.ai_addr, be->ha_addr.ai_addrlen);
                }
                (void)write(ctl, (void *)&dummy_be, sizeof(BACKEND));
                if(dummy = pthread_mutex_lock(&svc->mut))
                    logmsg(LOG_WARNING, "thr_control() lock: %s", strerror(dummy));
                else {
                    dump_sess(ctl, svc->sessions, svc->backends);
                    if(dummy = pthread_mutex_unlock(&svc->mut))
                        logmsg(LOG_WARNING, "thr_control() unlock: %s", strerror(dummy));
                }
                (void)write(ctl, (void *)&dummy_sess, sizeof(TABNODE));
            }
            (void)write(ctl, (void *)&dummy_svc, sizeof(SERVICE));
            break;
        case CTRL_EN_LSTN:
            if((lstn = sel_lstn(&cmd)) == NULL)
                logmsg(LOG_INFO, "thr_control() bad listener %d", cmd.listener);
            else
                lstn->disabled = 0;
            break;
        case CTRL_DE_LSTN:
            if((lstn = sel_lstn(&cmd)) == NULL)
                logmsg(LOG_INFO, "thr_control() bad listener %d", cmd.listener);
            else
                lstn->disabled = 1;
            break;
        case CTRL_EN_SVC:
            if((svc = sel_svc(&cmd)) == NULL)
                logmsg(LOG_INFO, "thr_control() bad service %d/%d", cmd.listener, cmd.service);
            else
                svc->disabled = 0;
            break;
        case CTRL_DE_SVC:
            if((svc = sel_svc(&cmd)) == NULL)
                logmsg(LOG_INFO, "thr_control() bad service %d/%d", cmd.listener, cmd.service);
            else
                svc->disabled = 1;
            break;
        case CTRL_EN_BE:
            if((svc = sel_svc(&cmd)) == NULL) {
                logmsg(LOG_INFO, "thr_control() bad service %d/%d", cmd.listener, cmd.service);
                break;
            }
            if((be = sel_be(&cmd)) == NULL)
                logmsg(LOG_INFO, "thr_control() bad backend %d/%d/%d", cmd.listener, cmd.service, cmd.backend);
            else
                kill_be(svc, be, BE_ENABLE);
            break;
        case CTRL_DE_BE:
            if((svc = sel_svc(&cmd)) == NULL) {
                logmsg(LOG_INFO, "thr_control() bad service %d/%d", cmd.listener, cmd.service);
                break;
            }
            if((be = sel_be(&cmd)) == NULL)
                logmsg(LOG_INFO, "thr_control() bad backend %d/%d/%d", cmd.listener, cmd.service, cmd.backend);
            else
                kill_be(svc, be, BE_DISABLE);
            break;
        case CTRL_ADD_SESS:
            if((svc = sel_svc(&cmd)) == NULL) {
                logmsg(LOG_INFO, "thr_control() bad service %d/%d", cmd.listener, cmd.service);
                break;
            }
            if((be = sel_be(&cmd)) == NULL) {
                logmsg(LOG_INFO, "thr_control() bad back-end %d/%d", cmd.listener, cmd.service);
                break;
            }
            if(ret_val = pthread_mutex_lock(&svc->mut))
                logmsg(LOG_WARNING, "thr_control() add session lock: %s", strerror(ret_val));
            t_add(svc->sessions, cmd.key, &be, sizeof(be));
            if(ret_val = pthread_mutex_unlock(&svc->mut))
                logmsg(LOG_WARNING, "thoriginalfiler_control() add session unlock: %s", strerror(ret_val));
            break;
        case CTRL_DEL_SESS:
            if((svc = sel_svc(&cmd)) == NULL) {
                logmsg(LOG_INFO, "thr_control() bad service %d/%d", cmd.listener, cmd.service);
                break;
            }
            if(ret_val = pthread_mutex_lock(&svc->mut))
                logmsg(LOG_WARNING, "thr_control() del session lock: %s", strerror(ret_val));
            t_remove(svc->sessions, cmd.key);
            if(ret_val = pthread_mutex_unlock(&svc->mut))
                logmsg(LOG_WARNING, "thr_control() del session unlock: %s", strerror(ret_val));
            break;
        default:
            logmsg(LOG_WARNING, "thr_control() unknown command");
            break;
        }
        close(ctl);
    }
}

void
SSLINFO_callback(const SSL *ssl, int where, int rc)
{
    RENEG_STATE *reneg_state;

    /* Get our thr_arg where we're tracking this connection info */
    if((reneg_state = (RENEG_STATE *)SSL_get_app_data(ssl)) == NULL)
        return;

    /* If we're rejecting renegotiations, move to ABORT if Client Hello is being read. */
    if((where & SSL_CB_ACCEPT_LOOP) && *reneg_state == RENEG_REJECT) {
        int state;

        state = SSL_get_state(ssl);
        if (state == SSL3_ST_SR_CLNT_HELLO_A || state == SSL23_ST_SR_CLNT_HELLO_A) {
           *reneg_state = RENEG_ABORT;
           logmsg(LOG_WARNING,"rejecting client initiated renegotiation");
        }
    } else if(where & SSL_CB_HANDSHAKE_DONE && *reneg_state == RENEG_INIT) {
       // Reject any followup renegotiations
       *reneg_state = RENEG_REJECT;
    }
}
