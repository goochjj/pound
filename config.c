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

static char *rcs_id = "$Id: config.c,v 2.0 2006/02/01 11:45:28 roseg Rel $";

/*
 * $Log: config.c,v $
 * Revision 2.0  2006/02/01 11:45:28  roseg
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
 * Revision 1.10  2006/02/01 11:19:51  roseg
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
 * Revision 1.5  2003/10/14 08:32:03  roseg
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
 * Revision 1.2  2003/01/20 15:15:05  roseg
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
 * Revision 0.11  2002/09/18 15:07:24  roseg
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
 * Revision 0.5  2002/07/04 12:23:18  roseg
 * code split
 *
 */

#ifndef MISS_FACILITYNAMES
#define SYSLOG_NAMES    1
#endif

#include    "pound.h"

#ifdef MISS_FACILITYNAMES

/* This is lifted verbatim from the Linux sys/syslog.h */

typedef struct _code {
	char	*c_name;
	int	c_val;
} CODE;

static CODE facilitynames[] = {
    { "auth", LOG_AUTH },
    { "authpriv", LOG_AUTHPRIV },
    { "cron", LOG_CRON },
    { "daemon", LOG_DAEMON },
    { "ftp", LOG_FTP },
    { "kern", LOG_KERN },
    { "lpr", LOG_LPR },
    { "mail", LOG_MAIL },
    { "mark", 0 },                  /* never used! */
    { "news", LOG_NEWS },
    { "security", LOG_AUTH },       /* DEPRECATED */
    { "syslog", LOG_SYSLOG },
    { "user", LOG_USER },
    { "uucp", LOG_UUCP },
    { "local0", LOG_LOCAL0 },
    { "local1", LOG_LOCAL1 },
    { "local2", LOG_LOCAL2 },
    { "local3", LOG_LOCAL3 },
    { "local4", LOG_LOCAL4 },
    { "local5", LOG_LOCAL5 },
    { "local6", LOG_LOCAL6 },
    { "local7", LOG_LOCAL7 },
    { NULL, -1 }
};
#endif

static regex_t  Empty, Comment, User, Group, RootJail, Daemon, LogFacility, LogLevel, Alive, SSLEngine;
static regex_t  ListenHTTP, ListenHTTPS, End, Address, Port, Cert, xHTTP, WebDAV, Client, CheckURL;
static regex_t  Err414, Err500, Err501, Err503, MaxRequest, HeadRemove, Change30x;
static regex_t  Service, URL, HeadRequire, HeadDeny, BackEnd, Priority, HAport, HAportAddr, Redirect, TimeOut;
static regex_t  Session, Type, TTL, ID;
static regex_t  ClientCert, AddHeader, Ciphers, CAlist, VerifyList, NoHTTPS11;

static regmatch_t   matches[5];

/*
 * parse a back-end
 */
BACKEND *
parse_be(FILE *f_conf)
{
    char        lin[MAXBUF];
    BACKEND     *res;
    int         has_addr, has_port;
    struct hostent      *host;

    if((res = (BACKEND *)malloc(sizeof(BACKEND))) == NULL) {
        logmsg(LOG_ERR, "BackEnd config: out of memory - aborted");
        exit(1);
    }
    memset(res, 0, sizeof(BACKEND));
    res->be_type = BACK_END;
    res->to = 15;
    res->alive = 1;
    memset(&res->addr, 0, sizeof(res->addr));
    res->priority = 1;
    memset(&res->HA, 0, sizeof(res->HA));
    res->url = NULL;
    res->next = NULL;
    has_addr = has_port = 0;
    while(fgets(lin, MAXBUF, f_conf)) {
        if(strlen(lin) > 0 && lin[strlen(lin) - 1] == '\n')
            lin[strlen(lin) - 1] = '\0';
        if(!regexec(&Empty, lin, 4, matches, 0) || !regexec(&Comment, lin, 4, matches, 0)) {
            /* comment or empty line */
            continue;
        } else if(!regexec(&Address, lin, 4, matches, 0)) {
            res->addr.sin_family = AF_INET;
            lin[matches[1].rm_eo] = '\0';
            if((host = gethostbyname(lin + matches[1].rm_so)) == NULL || host->h_addr_list[0] == NULL) {
                logmsg(LOG_ERR, "Unknown back-end host \"%s\"", lin + matches[1].rm_so);
                exit(1);
            }
            memcpy(&res->addr.sin_addr.s_addr, host->h_addr_list[0], sizeof(res->addr.sin_addr.s_addr));
            has_addr = 1;
        } else if(!regexec(&Port, lin, 4, matches, 0)) {
            res->addr.sin_port = (in_port_t)htons(atoi(lin + matches[1].rm_so));
            has_port = 1;
        } else if(!regexec(&Priority, lin, 4, matches, 0)) {
            res->priority = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&TimeOut, lin, 4, matches, 0)) {
            res->to = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&HAport, lin, 4, matches, 0)) {
            memcpy(&res->HA, &res->addr, sizeof(res->HA));
            res->HA.sin_port = (in_port_t)htons(atoi(lin + matches[1].rm_so));
        } else if(!regexec(&HAportAddr, lin, 4, matches, 0)) {
            res->HA.sin_family = AF_INET;
            lin[matches[1].rm_eo] = '\0';
            if((host = gethostbyname(lin + matches[1].rm_so)) == NULL || host->h_addr_list[0] == NULL) {
                logmsg(LOG_ERR, "Unknown HAport host \"%s\"", lin + matches[1].rm_so);
                exit(1);
            }
            memcpy(&res->HA.sin_addr.s_addr, host->h_addr_list[0], sizeof(res->HA.sin_addr.s_addr));
            res->HA.sin_port = (in_port_t)htons(atoi(lin + matches[2].rm_so));
        } else if(!regexec(&End, lin, 4, matches, 0)) {
            if(!has_addr || !has_port) {
                logmsg(LOG_ERR, "BackEnd missing Address or Port - aborted");
                exit(1);
            }
            return res;
        } else {
            logmsg(LOG_ERR, "unknown directive \"%s\" - aborted", lin);
            exit(1);
        }
    }

    logmsg(LOG_ERR, "BackEnd premature EOF");
    exit(1);
    return NULL;
}

/*
 * parse a session
 */
void
parse_sess(FILE *f_conf, SERVICE *svc)
{
    char        lin[MAXBUF], *cp;

    while(fgets(lin, MAXBUF, f_conf)) {
        if(strlen(lin) > 0 && lin[strlen(lin) - 1] == '\n')
            lin[strlen(lin) - 1] = '\0';
        if(!regexec(&Empty, lin, 4, matches, 0) || !regexec(&Comment, lin, 4, matches, 0)) {
            /* comment or empty line */
            continue;
        } else if(!regexec(&Type, lin, 4, matches, 0)) {
            if(svc->sess_type != S_NONE) {
                logmsg(LOG_ERR, "Multiple Session types in one Service - aborted");
                exit(1);
            }
            lin[matches[1].rm_eo] = '\0';
            cp = lin + matches[1].rm_so;
            if(!strcasecmp(cp, "IP"))
                svc->sess_type = S_IP;
            else if(!strcasecmp(cp, "COOKIE"))
                svc->sess_type = S_COOKIE;
            else if(!strcasecmp(cp, "PARM"))
                svc->sess_type = S_PARM;
            else if(!strcasecmp(cp, "BASIC"))
                svc->sess_type = S_BASIC;
            else if(!strcasecmp(cp, "HEADER"))
                svc->sess_type = S_HEADER;
            else {
                logmsg(LOG_ERR, "Unknown Session type \"%s\" - aborted", cp);
                exit(1);
            }
        } else if(!regexec(&TTL, lin, 4, matches, 0)) {
            svc->sess_ttl = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&ID, lin, 4, matches, 0)) {
            if(svc->sess_type != S_COOKIE && svc->sess_type != S_PARM && svc->sess_type != S_HEADER) {
                logmsg(LOG_ERR, "no ID permitted unless COOKIE/PARM/HEADER Session - aborted");
                exit(1);
            }
            lin[matches[1].rm_eo] = '\0';
            if((svc->sess_parm = strdup(lin + matches[1].rm_so)) == NULL) {
                logmsg(LOG_ERR, "ID config: out of memory - aborted");
                exit(1);
            }
        } else if(!regexec(&End, lin, 4, matches, 0)) {
            if(svc->sess_type == S_NONE) {
                logmsg(LOG_ERR, "Session type not defined - aborted");
                exit(1);
            }
            if(svc->sess_ttl <= 0) {
                logmsg(LOG_ERR, "Session TTL not defined - aborted");
                exit(1);
            }
            if((svc->sess_type == S_COOKIE || svc->sess_type == S_PARM || svc->sess_type == S_HEADER)
            && svc->sess_parm == NULL) {
                logmsg(LOG_ERR, "Session ID not defined - aborted");
                exit(1);
            }
            if(svc->sess_type == S_COOKIE) {
                snprintf(lin, MAXBUF - 1, "Cookie:.*[ \t]%s=([^;]*)", svc->sess_parm);
                if(regcomp(&svc->sess_pat, lin, REG_ICASE | REG_NEWLINE | REG_EXTENDED)) {
                    logmsg(LOG_ERR, "COOKIE pattern \"%s\" failed - aborted", lin);
                    exit(1);
                }
            } else if(svc->sess_type == S_PARM) {
                snprintf(lin, MAXBUF - 1, "[?&]%s=([^&;#]*)", svc->sess_parm);
                if(regcomp(&svc->sess_pat, lin, REG_ICASE | REG_NEWLINE | REG_EXTENDED)) {
                    logmsg(LOG_ERR, "PARM pattern \"%s\" failed - aborted", lin);
                    exit(1);
                }
            } else if(svc->sess_type == S_BASIC) {
                snprintf(lin, MAXBUF - 1, "Authorization:[ \t]*Basic[ \t]*([^ \t]*)[ \t]*");
                if(regcomp(&svc->sess_pat, lin, REG_ICASE | REG_NEWLINE | REG_EXTENDED)) {
                    logmsg(LOG_ERR, "BASIC pattern \"%s\" failed - aborted", lin);
                    exit(1);
                }
            } else if(svc->sess_type == S_HEADER) {
                snprintf(lin, MAXBUF - 1, "%s:[ \t]*([^ \t]*)[ \t]*", svc->sess_parm);
                if(regcomp(&svc->sess_pat, lin, REG_ICASE | REG_NEWLINE | REG_EXTENDED)) {
                    logmsg(LOG_ERR, "HEADER pattern \"%s\" failed - aborted", lin);
                    exit(1);
                }
            }
            return;
        } else {
            logmsg(LOG_ERR, "unknown directive \"%s\" - aborted", lin);
            exit(1);
        }
    }

    logmsg(LOG_ERR, "Session premature EOF");
    exit(1);
    return;
}

/*
 * parse a service
 */
SERVICE *
parse_service(FILE *f_conf)
{
    char        lin[MAXBUF];
    SERVICE     *res;
    BACKEND     *be;
    MATCHER     *m;

    if((res = (SERVICE *)malloc(sizeof(SERVICE))) == NULL) {
        logmsg(LOG_ERR, "Service config: out of memory - aborted");
        exit(1);
    }
    memset(res, 0, sizeof(SERVICE));
    res->sess_type = S_NONE;
    while(fgets(lin, MAXBUF, f_conf)) {
        if(strlen(lin) > 0 && lin[strlen(lin) - 1] == '\n')
            lin[strlen(lin) - 1] = '\0';
        if(!regexec(&Empty, lin, 4, matches, 0) || !regexec(&Comment, lin, 4, matches, 0)) {
            /* comment or empty line */
            continue;
        } else if(!regexec(&URL, lin, 4, matches, 0)) {
            if(res->url) {
                for(m = res->url; m->next; m = m->next)
                    ;
                if((m->next = (MATCHER *)malloc(sizeof(MATCHER))) == NULL) {
                    logmsg(LOG_ERR, "URL config: out of memory - aborted");
                    exit(1);
                }
                m = m->next;
            } else {
                if((res->url = (MATCHER *)malloc(sizeof(MATCHER))) == NULL) {
                    logmsg(LOG_ERR, "URL config: out of memory - aborted");
                    exit(1);
                }
                m = res->url;
            }
            memset(m, 0, sizeof(MATCHER));
            lin[matches[1].rm_eo] = '\0';
            if(regcomp(&m->pat, lin + matches[1].rm_so, REG_ICASE | REG_NEWLINE | REG_EXTENDED)) {
                logmsg(LOG_ERR, "URL bad pattern \"%s\" - aborted", lin + matches[1].rm_so);
                exit(1);
            }
        } else if(!regexec(&HeadRequire, lin, 4, matches, 0)) {
            if(res->req_head) {
                for(m = res->req_head; m->next; m = m->next)
                    ;
                if((m->next = (MATCHER *)malloc(sizeof(MATCHER))) == NULL) {
                    logmsg(LOG_ERR, "HeadRequire config: out of memory - aborted");
                    exit(1);
                }
                m = m->next;
            } else {
                if((res->req_head = (MATCHER *)malloc(sizeof(MATCHER))) == NULL) {
                    logmsg(LOG_ERR, "HeadRequire config: out of memory - aborted");
                    exit(1);
                }
                m = res->req_head;
            }
            memset(m, 0, sizeof(MATCHER));
            lin[matches[1].rm_eo] = '\0';
            if(regcomp(&m->pat, lin + matches[1].rm_so, REG_ICASE | REG_NEWLINE | REG_EXTENDED)) {
                logmsg(LOG_ERR, "HeadRequire bad pattern \"%s\" - aborted", lin + matches[1].rm_so);
                exit(1);
            }
        } else if(!regexec(&HeadDeny, lin, 4, matches, 0)) {
            if(res->deny_head) {
                for(m = res->deny_head; m->next; m = m->next)
                    ;
                if((m->next = (MATCHER *)malloc(sizeof(MATCHER))) == NULL) {
                    logmsg(LOG_ERR, "HeadDeny config: out of memory - aborted");
                    exit(1);
                }
                m = m->next;
            } else {
                if((res->deny_head = (MATCHER *)malloc(sizeof(MATCHER))) == NULL) {
                    logmsg(LOG_ERR, "HeadDeny config: out of memory - aborted");
                    exit(1);
                }
                m = res->deny_head;
            }
            memset(m, 0, sizeof(MATCHER));
            lin[matches[1].rm_eo] = '\0';
            if(regcomp(&m->pat, lin + matches[1].rm_so, REG_ICASE | REG_NEWLINE | REG_EXTENDED)) {
                logmsg(LOG_ERR, "HeadDeny bad pattern \"%s\" - aborted", lin + matches[1].rm_so);
                exit(1);
            }
        } else if(!regexec(&Redirect, lin, 4, matches, 0)) {
            if(res->backends) {
                for(be = res->backends; be->next; be = be->next)
                    ;
                if((be->next = (BACKEND *)malloc(sizeof(BACKEND))) == NULL) {
                    logmsg(LOG_ERR, "Redirect config: out of memory - aborted");
                    exit(1);
                }
                be = be->next;
            } else {
                if((res->backends = (BACKEND *)malloc(sizeof(BACKEND))) == NULL) {
                    logmsg(LOG_ERR, "Redirect config: out of memory - aborted");
                    exit(1);
                }
                be = res->backends;
            }
            memset(be, 0, sizeof(BACKEND));
            be->be_type = REDIRECTOR;
            be->priority = 1;
            be->alive = 1;
            lin[matches[1].rm_eo] = '\0';
            if((be->url = strdup(lin + matches[1].rm_so)) == NULL) {
                logmsg(LOG_ERR, "Redirector config: out of memory - aborted");
                exit(1);
            }
        } else if(!regexec(&BackEnd, lin, 4, matches, 0)) {
            if(res->backends) {
                for(be = res->backends; be->next; be = be->next)
                    ;
                be->next = parse_be(f_conf);
            } else
                res->backends = parse_be(f_conf);
        } else if(!regexec(&Session, lin, 4, matches, 0)) {
            parse_sess(f_conf, res);
        } else if(!regexec(&End, lin, 4, matches, 0)) {
            for(be = res->backends; be; be = be->next)
                res->tot_pri += be->priority;
            return res;
        } else {
            logmsg(LOG_ERR, "unknown directive \"%s\" - aborted", lin);
            exit(1);
        }
    }

    logmsg(LOG_ERR, "Service premature EOF");
    exit(1);
    return NULL;
}

/*
 * return the file contents as a string
 */
static char *
file2str(char *fname)
{
    char    *res;
    struct stat st;
    int     fin;

    if(stat(fname, &st)) {
        logmsg(LOG_ERR, "can't stat Err file \"%s\" (%s) - aborted", fname, strerror(errno));
        exit(1);
    }
    if((fin = open(fname, O_RDONLY)) < 0) {
        logmsg(LOG_ERR, "can't open Err file \"%s\" (%s) - aborted", fname, strerror(errno));
        exit(1);
    }
    if((res = malloc(st.st_size + 1)) == NULL) {
        logmsg(LOG_ERR, "can't alloc Err file \"%s\" (out of memory) - aborted", fname);
        exit(1);
    }
    if(read(fin, res, st.st_size) != st.st_size) {
        logmsg(LOG_ERR, "can't read Err file \"%s\" (%s) - aborted", fname, strerror(errno));
        exit(1);
    }
    res[st.st_size] = '\0';
    close(fin);
    return res;
}

/*
 * parse an HTTP listener
 */
LISTENER *
parse_HTTP(FILE *f_conf)
{
    char        lin[MAXBUF];
    LISTENER    *res;
    SERVICE     *svc;
    MATCHER     *m;
    struct hostent      *host;
    int         has_addr, has_port;

    if((res = (LISTENER *)malloc(sizeof(LISTENER))) == NULL) {
        logmsg(LOG_ERR, "ListenHTTP config: out of memory - aborted");
        exit(1);
    }
    memset(res, 0, sizeof(LISTENER));
    res->to = 10;
    res->err414 = "Request URI is too long";
    res->err500 = "An internal server error occurred. Please try again later.";
    res->err501 = "This method may not be used.";
    res->err503 = "The service is not available. Please try again later.";
    if(regcomp(&res->url_pat, ".*", REG_ICASE | REG_NEWLINE | REG_EXTENDED)) {
        logmsg(LOG_ERR, "CheckURL bad default pattern - aborted");
        exit(1);
    }
    has_addr = has_port = 0;
    while(fgets(lin, MAXBUF, f_conf)) {
        if(strlen(lin) > 0 && lin[strlen(lin) - 1] == '\n')
            lin[strlen(lin) - 1] = '\0';
        if(!regexec(&Empty, lin, 4, matches, 0) || !regexec(&Comment, lin, 4, matches, 0)) {
            /* comment or empty line */
            continue;
        } else if(!regexec(&Address, lin, 4, matches, 0)) {
            res->addr.sin_family = AF_INET;
            lin[matches[1].rm_eo] = '\0';
            if((host = gethostbyname(lin + matches[1].rm_so)) == NULL || host->h_addr_list[0] == NULL) {
                logmsg(LOG_ERR, "Unknown Listener address \"%s\"", lin + matches[1].rm_so);
                exit(1);
            }
            memcpy(&res->addr.sin_addr.s_addr, host->h_addr_list[0], sizeof(res->addr.sin_addr.s_addr));
            has_addr = 1;
        } else if(!regexec(&Port, lin, 4, matches, 0)) {
            res->addr.sin_port = (in_port_t)htons(atoi(lin + matches[1].rm_so));
            has_port = 1;
        } else if(!regexec(&xHTTP, lin, 4, matches, 0)) {
            res->xHTTP = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&WebDAV, lin, 4, matches, 0)) {
            res->webDAV = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&Client, lin, 4, matches, 0)) {
            res->to = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&CheckURL, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            regfree(&res->url_pat);
            if(regcomp(&res->url_pat, lin + matches[1].rm_so, REG_ICASE | REG_NEWLINE | REG_EXTENDED)) {
                logmsg(LOG_ERR, "CheckURL bad pattern \"%s\" - aborted", lin + matches[1].rm_so);
                exit(1);
            }
        } else if(!regexec(&Err414, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            res->err414 = file2str(lin + matches[1].rm_so);
        } else if(!regexec(&Err500, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            res->err500 = file2str(lin + matches[1].rm_so);
        } else if(!regexec(&Err501, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            res->err501 = file2str(lin + matches[1].rm_so);
        } else if(!regexec(&Err503, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            res->err503 = file2str(lin + matches[1].rm_so);
        } else if(!regexec(&MaxRequest, lin, 4, matches, 0)) {
            res->max_req = atol(lin + matches[1].rm_so);
        } else if(!regexec(&HeadRemove, lin, 4, matches, 0)) {
            if(res->head_off) {
                for(m = res->head_off; m->next; m = m->next)
                    ;
                if((m->next = (MATCHER *)malloc(sizeof(MATCHER))) == NULL) {
                    logmsg(LOG_ERR, "HeadRemove config: out of memory - aborted");
                    exit(1);
                }
                m = m->next;
            } else {
                if((res->head_off = (MATCHER *)malloc(sizeof(MATCHER))) == NULL) {
                    logmsg(LOG_ERR, "HeadRemove config: out of memory - aborted");
                    exit(1);
                }
                m = res->head_off;
            }
            memset(m, 0, sizeof(MATCHER));
            lin[matches[1].rm_eo] = '\0';
            if(regcomp(&m->pat, lin + matches[1].rm_so, REG_ICASE | REG_NEWLINE | REG_EXTENDED)) {
                logmsg(LOG_ERR, "HeadRemove bad pattern \"%s\" - aborted", lin + matches[1].rm_so);
                exit(1);
            }
        } else if(!regexec(&Change30x, lin, 4, matches, 0)) {
            res->change30x = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&Service, lin, 4, matches, 0)) {
            if(res->services == NULL)
                res->services = parse_service(f_conf);
            else {
                for(svc = res->services; svc->next; svc = svc->next)
                    ;
                svc->next = parse_service(f_conf);
            }
        } else if(!regexec(&End, lin, 4, matches, 0)) {
            if(!has_addr || !has_port) {
                logmsg(LOG_ERR, "ListenHTTP missing Address or Port - aborted");
                exit(1);
            }
            return res;
        } else {
            logmsg(LOG_ERR, "unknown directive \"%s\" - aborted", lin);
            exit(1);
        }
    }

    logmsg(LOG_ERR, "ListenHTTP premature EOF");
    exit(1);
    return NULL;
}
/*
 * Dummy certificate verification - always OK
 */
static int
verify_OK(int pre_ok, X509_STORE_CTX *ctx)
{
    return 1;
}

/*
 * parse an HTTPS listener
 */
LISTENER *
parse_HTTPS(FILE *f_conf)
{
    char        lin[MAXBUF];
    LISTENER    *res;
    SERVICE     *svc;
    MATCHER     *m;
    struct hostent      *host;
    int         has_addr, has_port, has_cert;

    if((res = (LISTENER *)malloc(sizeof(LISTENER))) == NULL) {
        logmsg(LOG_ERR, "ListenHTTPS config: out of memory - aborted");
        exit(1);
    }
    memset(res, 0, sizeof(LISTENER));
    if((res->ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
        logmsg(LOG_ERR, "SSL_CTX_new failed - aborted");
        exit(1);
    }

    res->to = 10;
    res->err414 = "Request URI is too long";
    res->err500 = "An internal server error occurred. Please try again later.";
    res->err501 = "This method may not be used.";
    res->err503 = "The service is not available. Please try again later.";
    if(regcomp(&res->url_pat, ".*", REG_ICASE | REG_NEWLINE | REG_EXTENDED)) {
        logmsg(LOG_ERR, "CheckURL bad default pattern - aborted");
        exit(1);
    }
    has_addr = has_port = has_cert = 0;
    while(fgets(lin, MAXBUF, f_conf)) {
        if(strlen(lin) > 0 && lin[strlen(lin) - 1] == '\n')
            lin[strlen(lin) - 1] = '\0';
        if(!regexec(&Empty, lin, 4, matches, 0) || !regexec(&Comment, lin, 4, matches, 0)) {
            /* comment or empty line */
            continue;
        } else if(!regexec(&Address, lin, 4, matches, 0)) {
            res->addr.sin_family = AF_INET;
            lin[matches[1].rm_eo] = '\0';
            if((host = gethostbyname(lin + matches[1].rm_so)) == NULL || host->h_addr_list[0] == NULL) {
                logmsg(LOG_ERR, "Unknown Listener address \"%s\"", lin + matches[1].rm_so);
                exit(1);
            }
            memcpy(&res->addr.sin_addr.s_addr, host->h_addr_list[0], sizeof(res->addr.sin_addr.s_addr));
            has_addr = 1;
        } else if(!regexec(&Port, lin, 4, matches, 0)) {
            res->addr.sin_port = (in_port_t)htons(atoi(lin + matches[1].rm_so));
            has_port = 1;
        } else if(!regexec(&xHTTP, lin, 4, matches, 0)) {
            res->xHTTP = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&WebDAV, lin, 4, matches, 0)) {
            res->webDAV = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&Client, lin, 4, matches, 0)) {
            res->to = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&CheckURL, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            regfree(&res->url_pat);
            if(regcomp(&res->url_pat, lin + matches[1].rm_so, REG_ICASE | REG_NEWLINE | REG_EXTENDED)) {
                logmsg(LOG_ERR, "CheckURL bad pattern \"%s\" - aborted", lin + matches[1].rm_so);
                exit(1);
            }
        } else if(!regexec(&Err414, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            res->err414 = file2str(lin + matches[1].rm_so);
        } else if(!regexec(&Err500, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            res->err500 = file2str(lin + matches[1].rm_so);
        } else if(!regexec(&Err501, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            res->err501 = file2str(lin + matches[1].rm_so);
        } else if(!regexec(&Err503, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            res->err503 = file2str(lin + matches[1].rm_so);
        } else if(!regexec(&MaxRequest, lin, 4, matches, 0)) {
            res->max_req = atol(lin + matches[1].rm_so);
        } else if(!regexec(&HeadRemove, lin, 4, matches, 0)) {
            if(res->head_off) {
                for(m = res->head_off; m->next; m = m->next)
                    ;
                if((m->next = (MATCHER *)malloc(sizeof(MATCHER))) == NULL) {
                    logmsg(LOG_ERR, "HeadRemove config: out of memory - aborted");
                    exit(1);
                }
                m = m->next;
            } else {
                if((res->head_off = (MATCHER *)malloc(sizeof(MATCHER))) == NULL) {
                    logmsg(LOG_ERR, "HeadRemove config: out of memory - aborted");
                    exit(1);
                }
                m = res->head_off;
            }
            memset(m, 0, sizeof(MATCHER));
            lin[matches[1].rm_eo] = '\0';
            if(regcomp(&m->pat, lin + matches[1].rm_so, REG_ICASE | REG_NEWLINE | REG_EXTENDED)) {
                logmsg(LOG_ERR, "HeadRemove bad pattern \"%s\" - aborted", lin + matches[1].rm_so);
                exit(1);
            }
        } else if(!regexec(&Change30x, lin, 4, matches, 0)) {
            res->change30x = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&Cert, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            if(SSL_CTX_use_certificate_chain_file(res->ctx, lin + matches[1].rm_so) != 1) {
                logmsg(LOG_ERR, "SSL_CTX_use_certificate_chain_file \"%s\" failed - aborted",
                    lin + matches[1].rm_so);
                exit(1);
            }
            if(SSL_CTX_use_PrivateKey_file(res->ctx, lin + matches[1].rm_so, SSL_FILETYPE_PEM) != 1) {
                logmsg(LOG_ERR, "SSL_CTX_use_PrivateKey_file \"%s\" failed - aborted",
                    lin + matches[1].rm_so);
                exit(1);
            }
            if(SSL_CTX_check_private_key(res->ctx) != 1) {
                logmsg(LOG_ERR, "SSL_CTX_check_private_key \"%s\" failed - aborted",
                    lin + matches[1].rm_so);
                exit(1);
            }
            has_cert = 1;
        } else if(!regexec(&ClientCert, lin, 4, matches, 0)) {
            switch(atoi(lin + matches[1].rm_so)) {
            case 0:
                /* don't ask */
                SSL_CTX_set_verify(res->ctx, SSL_VERIFY_NONE, NULL);
                break;
            case 1:
                /* ask but OK if no client certificate */
                SSL_CTX_set_verify(res->ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, NULL);
                SSL_CTX_set_verify_depth(res->ctx, atoi(lin + matches[2].rm_so));
                break;
            case 2:
                /* ask and fail if no client certificate */
                SSL_CTX_set_verify(res->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
                SSL_CTX_set_verify_depth(res->ctx, atoi(lin + matches[2].rm_so));
                break;
            case 3:
                /* ask but do not verify client certificate */
                SSL_CTX_set_verify(res->ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, verify_OK);
                SSL_CTX_set_verify_depth(res->ctx, atoi(lin + matches[2].rm_so));
                break;
            }
        } else if(!regexec(&AddHeader, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            if((res->ssl_head = strdup(lin + matches[1].rm_so)) == NULL) {
                logmsg(LOG_ERR, "AddHeader config: out of memory - aborted");
                exit(1);
            }
        } else if(!regexec(&Ciphers, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            SSL_CTX_set_cipher_list(res->ctx, lin + matches[1].rm_so);
        } else if(!regexec(&CAlist, lin, 4, matches, 0)) {
            STACK_OF(X509_NAME) *cert_names;

            lin[matches[1].rm_eo] = '\0';
            if((cert_names = SSL_load_client_CA_file(lin + matches[1].rm_so)) == NULL) {
                logmsg(LOG_ERR, "SSL_load_client_CA_file \"%s\" failed - aborted", lin + matches[1].rm_so);
                exit(1);
            }
            SSL_CTX_set_client_CA_list(res->ctx, cert_names);
        } else if(!regexec(&VerifyList, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            if(SSL_CTX_load_verify_locations(res->ctx, lin + matches[1].rm_so, NULL) != 1) {
                logmsg(LOG_ERR, "SSL_CTX_load_verify_locations \"%s\" failed - aborted", lin + matches[1].rm_so);
                exit(1);
            }
        } else if(!regexec(&NoHTTPS11, lin, 4, matches, 0)) {
            res->noHTTPS11 = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&Service, lin, 4, matches, 0)) {
            if(res->services == NULL)
                res->services = parse_service(f_conf);
            else {
                for(svc = res->services; svc->next; svc = svc->next)
                    ;
                svc->next = parse_service(f_conf);
            }
        } else if(!regexec(&End, lin, 4, matches, 0)) {
            X509_STORE  *store;

            if(!has_addr || !has_port || !has_cert) {
                logmsg(LOG_ERR, "ListenHTTPS missing Address, Port or Certificate - aborted");
                exit(1);
            }
            SSL_CTX_set_mode(res->ctx, SSL_MODE_AUTO_RETRY);
            SSL_CTX_set_options(res->ctx, SSL_OP_ALL);
            sprintf(lin, "%d-Pound-%l", getpid(), random());
            SSL_CTX_set_session_id_context(res->ctx, (unsigned char *)lin, strlen(lin));
            SSL_CTX_set_tmp_rsa_callback(res->ctx, RSA_tmp_callback);
#if HAVE_X509_STORE_SET_FLAGS
            /* add the CRL stuff */
            if((store = SSL_CTX_get_cert_store(res->ctx)) != NULL)
                X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
            else
                logmsg(LOG_WARNING, "SSL_CTX_get_cert_store failed!");
#endif
            return res;
        } else {
            logmsg(LOG_ERR, "unknown directive \"%s\" - aborted", lin);
            exit(1);
        }
    }

    logmsg(LOG_ERR, "ListenHTTPS premature EOF");
    exit(1);
    return NULL;
}

/*
 * parse the config file
 */
void
parse_file(FILE *f_conf)
{
    char        lin[MAXBUF];
    SERVICE     *svc;
    LISTENER    *lstn;
    int         i;
#if HAVE_OPENSSL_ENGINE_H
    ENGINE      *e;
#endif

    while(fgets(lin, MAXBUF, f_conf)) {
        if(strlen(lin) > 0 && lin[strlen(lin) - 1] == '\n')
            lin[strlen(lin) - 1] = '\0';
        if(!regexec(&Empty, lin, 4, matches, 0) || !regexec(&Comment, lin, 4, matches, 0)) {
            /* comment or empty line */
            continue;
        } else if(!regexec(&User, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            if((user = strdup(lin + matches[1].rm_so)) == NULL) {
                logmsg(LOG_ERR, "User config: out of memory - aborted");
                exit(1);
            }
        } else if(!regexec(&Group, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            if((group = strdup(lin + matches[1].rm_so)) == NULL) {
                logmsg(LOG_ERR, "Group config: out of memory - aborted");
                exit(1);
            }
        } else if(!regexec(&RootJail, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            if((root_jail = strdup(lin + matches[1].rm_so)) == NULL) {
                logmsg(LOG_ERR, "RootJail config: out of memory - aborted");
                exit(1);
            }
        } else if(!regexec(&Daemon, lin, 4, matches, 0)) {
            daemonize = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&LogFacility, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            for(i = 0; facilitynames[i].c_name; i++)
                if(!strcmp(facilitynames[i].c_name, lin + matches[1].rm_so)) {
                    log_facility = facilitynames[i].c_val;
                    break;
                }
        } else if(!regexec(&LogLevel, lin, 4, matches, 0)) {
            log_level = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&Alive, lin, 4, matches, 0)) {
            alive_to = atoi(lin + matches[1].rm_so);
#if HAVE_OPENSSL_ENGINE_H
        } else if(!regexec(&SSLEngine, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
            ENGINE_load_builtin_engines();
#endif
            if (!(e = ENGINE_by_id(lin + matches[1].rm_so))) {
                logmsg(LOG_ERR, "could not find %s engine", lin + matches[1].rm_so);
                exit(1);
            }
            if(!ENGINE_init(e)) {
                ENGINE_free(e);
                logmsg(LOG_ERR, "could not init %s engine", lin + matches[1].rm_so);
                exit(1);
            }
            if(!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
                ENGINE_free(e);
                logmsg(LOG_ERR, "could not set all defaults");
                exit(1);
            }
            ENGINE_finish(e);
            ENGINE_free(e);
#endif
        } else if(!regexec(&ListenHTTP, lin, 4, matches, 0)) {
            if(listeners == NULL)
                listeners = parse_HTTP(f_conf);
            else {
                for(lstn = listeners; lstn->next; lstn = lstn->next)
                    ;
                lstn->next = parse_HTTP(f_conf);
            }
        } else if(!regexec(&ListenHTTPS, lin, 4, matches, 0)) {
            if(listeners == NULL)
                listeners = parse_HTTPS(f_conf);
            else {
                for(lstn = listeners; lstn->next; lstn = lstn->next)
                    ;
                lstn->next = parse_HTTPS(f_conf);
            }
        } else if(!regexec(&Service, lin, 4, matches, 0)) {
            if(services == NULL)
                services = parse_service(f_conf);
            else {
                for(svc = services; svc->next; svc = svc->next)
                    ;
                svc->next = parse_service(f_conf);
            }
        } else {
            logmsg(LOG_ERR, "unknown directive \"%s\" - aborted", lin);
            exit(1);
        }
    }
    return;
}

/*
 * prepare to parse the arguments/config file
 */
void
config_parse(int argc, char **argv)
{
    char    *conf_name;
    FILE    *f_conf;
    int     c_opt, check_only;

    if(regcomp(&Empty, "^[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Comment, "^[ \t]*#.*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&User, "^[ \t]*User[ \t]+\"(.+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Group, "^[ \t]*Group[ \t]+\"(.+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&RootJail, "^[ \t]*RootJail[ \t]+\"(.+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Daemon, "^[ \t]*Daemon[ \t]+([01])[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&LogFacility, "^[ \t]*LogFacility[ \t]+([a-z0-9]+)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&LogLevel, "^[ \t]*LogLevel[ \t]+([0-4])[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Alive, "^[ \t]*Alive[ \t]+([1-9][0-9]*)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&SSLEngine, "^[ \t]*SSLEngine[ \t]+\"(.+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&ListenHTTP, "^[ \t]*ListenHTTP[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&ListenHTTPS, "^[ \t]*ListenHTTPS[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&End, "^[ \t]*End[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Address, "^[ \t]*Address[ \t]+([^ \t]+)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Port, "^[ \t]*Port[ \t]+([1-9][0-9]*)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Cert, "^[ \t]*Cert[ \t]+\"(.+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&xHTTP, "^[ \t]*xHTTP[ \t]+([01])[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&WebDAV, "^[ \t]*WebDAV[ \t]+([01])[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Client, "^[ \t]*Client[ \t]+([1-9][0-9]*)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&CheckURL, "^[ \t]*CheckURL[ \t]+\"(.+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Err414, "^[ \t]*Err414[ \t]+\"(.+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Err500, "^[ \t]*Err500[ \t]+\"(.+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Err501, "^[ \t]*Err501[ \t]+\"(.+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Err503, "^[ \t]*Err503[ \t]+\"(.+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&MaxRequest, "^[ \t]*MaxRequest[ \t]+([1-9][0-9]*)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&HeadRemove, "^[ \t]*HeadRemove[ \t]+\"(.+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Change30x, "^[ \t]*Change30x[ \t]+([01])[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Service, "^[ \t]*Service[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&URL, "^[ \t]*URL[ \t]+\"(.+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&HeadRequire, "^[ \t]*HeadRequire[ \t]+\"(.+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&HeadDeny, "^[ \t]*HeadDeny[ \t]+\"(.+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&BackEnd, "^[ \t]*BackEnd[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Priority, "^[ \t]*Priority[ \t]+([1-9])[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&TimeOut, "^[ \t]*TimeOut[ \t]+([1-9][0-9]*)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&HAport, "^[ \t]*HAport[ \t]+([1-9][0-9]*)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&HAportAddr, "^[ \t]*HAport[ \t]+([^ \t]+)[ \t]+([1-9][0-9]*)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Redirect, "^[ \t]*Redirect[ \t]+\"(.+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Session, "^[ \t]*Session[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Type, "^[ \t]*Type[ \t]+([^ \t]+)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&TTL, "^[ \t]*TTL[ \t]+([1-9][0-9]*)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&ID, "^[ \t]*ID[ \t]+\"(.+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&ClientCert, "^[ \t]*ClientCert[ \t]+([0-3])[ \t]+[1-9][ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&AddHeader, "^[ \t]*AddHeader[ \t]+\"(.+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Ciphers, "^[ \t]*Ciphers[ \t]+\"(.+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&CAlist, "^[ \t]*CAlist[ \t]+\"(.+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&VerifyList, "^[ \t]*VerifyList[ \t]+\"(.+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&NoHTTPS11, "^[ \t]*NoHTTPS11[ \t]+([0-2])[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    ) {
        logmsg(LOG_ERR, "bad config Regex - aborted");
        exit(1);
    }

    opterr = 0;
    check_only = 0;
    conf_name = F_CONF;
    pid_name = F_PID;

    while((c_opt = getopt(argc, argv, "f:cvVp:")) > 0)
        switch(c_opt) {
        case 'f':
            conf_name = optarg;
            break;
        case 'p':
            pid_name = optarg;
            break;
        case 'c':
            check_only = 1;
            break;
        case 'v':
            print_log = 1;
            break;
        case 'V':
            print_log = 1;
            logmsg(LOG_DEBUG, "Version %s", VERSION);
            logmsg(LOG_DEBUG, "Exiting...");
            exit(0);
            break;
        default:
            logmsg(LOG_ERR, "bad flag -%c", optopt);
            exit(1);
            break;
        }
    if(optind < argc) {
        logmsg(LOG_ERR, "unknown extra arguments (%s...)", argv[optind]);
        exit(1);
    }

    if((f_conf = fopen(conf_name, "rt")) == NULL) {
        logmsg(LOG_ERR, "can't open configuration file \"%s\" (%s) - aborted", conf_name, strerror(errno));
        exit(1);
    }

    user = NULL;
    group = NULL;
    root_jail = NULL;

    alive_to = 30;
    daemonize = 1;
    log_facility = LOG_DAEMON;
    log_level = 1;

    services = NULL;
    listeners = NULL;

    parse_file(f_conf);

    fclose(f_conf);

    if(check_only) {
        logmsg(LOG_INFO, "Config file %s is OK", conf_name);
        exit(0);
    }

    if(listeners == NULL) {
        logmsg(LOG_ERR, "no listeners define - aborted");
        exit(1);
    }

    regfree(&Empty);
    regfree(&Comment);
    regfree(&User);
    regfree(&Group);
    regfree(&RootJail);
    regfree(&Daemon);
    regfree(&LogFacility);
    regfree(&LogLevel);
    regfree(&Alive);
    regfree(&SSLEngine);
    regfree(&ListenHTTP);
    regfree(&ListenHTTPS);
    regfree(&End);
    regfree(&Address);
    regfree(&Port);
    regfree(&Cert);
    regfree(&xHTTP);
    regfree(&WebDAV);
    regfree(&Client);
    regfree(&CheckURL);
    regfree(&Err414);
    regfree(&Err500);
    regfree(&Err501);
    regfree(&Err503);
    regfree(&MaxRequest);
    regfree(&HeadRemove);
    regfree(&Change30x);
    regfree(&Service);
    regfree(&URL);
    regfree(&HeadRequire);
    regfree(&HeadDeny);
    regfree(&BackEnd);
    regfree(&Priority);
    regfree(&TimeOut);
    regfree(&HAport);
    regfree(&HAportAddr);
    regfree(&Redirect);
    regfree(&Session);
    regfree(&Type);
    regfree(&TTL);
    regfree(&ID);
    regfree(&ClientCert);
    regfree(&AddHeader);
    regfree(&Ciphers);
    regfree(&CAlist);
    regfree(&VerifyList);
    regfree(&NoHTTPS11);

    return;
}
