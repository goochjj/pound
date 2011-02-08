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

static char *rcs_id = "$Id: config.c,v 1.1 2003/01/09 01:28:39 roseg Rel roseg $";

/*
 * $Log: config.c,v $
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

#include    "pound.h"

static void
parse_file(char *fname)
{
    FILE                *fconf;
    char                lin[MAXBUF], pat[MAXBUF];
    regex_t             Empty, Comment, ListenHTTP, ListenHTTPS, HTTPSHeaders, HTTPSHeadersOn,
                        SessionIP, SessionURL, SessionCOOKIE,
                        User, Group, RootJail, ExtendedHTTP, WebDAV, LogLevel, Alive,
                        Client, UrlGroup, HeadRequire, HeadDeny, BackEnd, BackEndHA, EndGroup;
    regex_t             *req, *deny;
    regmatch_t          matches[5];
    struct sockaddr_in  addr, alive_addr;
    struct hostent      *host;
    BACKEND             *be;
    int                 j, k, tot_be, tot_groups, tot_req, tot_deny, in_group, n_http, n_https;

    if(regcomp(&Empty, "^[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Comment, "^[ \t]*#.*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&ListenHTTP, "^[ \t]*ListenHTTP[ \t]+([^,]+,[1-9][0-9]*)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&ListenHTTPS, "^[ \t]*ListenHTTPS[ \t]+([^,]+,[1-9][0-9]*)[ \t]+([^ \t]+)[ \t]*([^ \t]*)[ \t]*$",
        REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&HTTPSHeaders, "^[ \t]*HTTPSHeaders[ \t]+\"([^\"]*)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&HTTPSHeadersOn, "^[ \t]*HTTPSHeaders[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&SessionIP, "^[ \t]*Session[ \t]+IP[ \t]+([0-9-][0-9]*)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&SessionURL, "^[ \t]*Session[ \t]+URL[ \t]+([^ \t]+)[ \t]+([0-9-][0-9]*)[ \t]*$",
        REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&SessionCOOKIE, "^[ \t]*Session[ \t]+Cookie[ \t]+([^ \t]+)[ \t]+([0-9-][0-9]*)[ \t]*$",
        REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&User, "^[ \t]*User[ \t]+([^ \t]+)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Group, "^[ \t]*Group[ \t]+([^ \t]+)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&RootJail, "^[ \t]*RootJail[ \t]+([^ \t]+)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&ExtendedHTTP, "^[ \t]*ExtendedHTTP[ \t]+([01])[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&WebDAV, "^[ \t]*WebDAV[ \t]+([01])[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&LogLevel, "^[ \t]*LogLevel[ \t]+([0123])[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Alive, "^[ \t]*Alive[ \t]+([1-9][0-9]*)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Client, "^[ \t]*Client[ \t]+([1-9-][0-9]*)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&UrlGroup, "^[ \t]*UrlGroup[ \t]+\"([^\"]+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&BackEnd, "^[ \t]*BackEnd[ \t]+([^,]+),([0-9]+),([1-9])[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&BackEndHA, "^[ \t]*BackEnd[ \t]+([^,]+),([0-9]+),([1-9]),([0-9]+)[ \t]*$",
        REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&HeadRequire, "^[ \t]*HeadRequire[ \t]+([^ \t]+)[ \t]+\"([^\"]+)\"[ \t]*$",
        REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&HeadDeny, "^[ \t]*HeadDeny[ \t]+([^ \t]+)[ \t]+\"([^\"]+)\"[ \t]*$",
        REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&EndGroup, "^[ \t]*EndGroup[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    ) {
        syslog(LOG_ERR, "bad config Regex - aborted");
        exit(1);
    }

    if((fconf = fopen(fname, "rt")) == NULL) {
        syslog(LOG_ERR, "can't open configuration file \"%s\" (%m) - aborted", fname);
        exit(1);
    }

    /* first pass - just find number of groups and backends so we can allocate correctly */
    for(n_http = n_https = tot_be = tot_groups = tot_req = tot_deny = 0; fgets(lin, MAXBUF, fconf); ) {
        if(!regexec(&ListenHTTP, lin, 4, matches, 0))
            n_http++;
        else if(!regexec(&ListenHTTPS, lin, 4, matches, 0))
            n_https++;
        else if(!regexec(&UrlGroup, lin, 4, matches, 0))
            tot_groups++;
        else if(!regexec(&BackEnd, lin, 4, matches, 0))
            tot_be += atoi(lin + matches[3].rm_so);
        else if(!regexec(&BackEndHA, lin, 5, matches, 0))
            tot_be += atoi(lin + matches[3].rm_so);
        else if(!regexec(&HeadRequire, lin, 4, matches, 0))
            tot_req++;
        else if(!regexec(&HeadDeny, lin, 4, matches, 0))
            tot_deny++;
    }
    rewind(fconf);

    if((http = (char **)malloc(sizeof(char *) * (n_http + 1))) == NULL
    || (https = (char **)malloc(sizeof(char *) * (n_https + 1))) == NULL
    || (cert = (char **)malloc(sizeof(char *) * (n_https + 1))) == NULL
    || (ciphers = (char **)malloc(sizeof(char *) * (n_https + 1))) == NULL) {
        syslog(LOG_ERR, "listen setup: out of memory - aborted");
        exit(1);
    }
    http[n_http] = https[n_https] = cert[n_https] = NULL;

    if((groups = (GROUP **)malloc(sizeof(GROUP *) * (tot_groups + 1))) == NULL) {
        syslog(LOG_ERR, "groups setup: out of memory - aborted");
        exit(1);
    }
    groups[tot_groups] = NULL;

    if((be = (BACKEND *)malloc(sizeof(BACKEND) * tot_be)) == NULL) {
        syslog(LOG_ERR, "backend setup: out of memory - aborted");
        exit(1);
    }
    if(tot_req > 0) {
        if((req = (regex_t *)malloc(sizeof(regex_t) * tot_req)) == NULL) {
            syslog(LOG_ERR, "req setup: out of memory - aborted");
            exit(1);
        }
    } else
        req = NULL;
    if(tot_deny > 0) {
        if((deny = (regex_t *)malloc(sizeof(regex_t) * tot_deny)) == NULL) {
            syslog(LOG_ERR, "deny setup: out of memory - aborted");
            exit(1);
        }
    } else
        deny = NULL;

    n_http = n_https = tot_groups = in_group = 0;
    while(fgets(lin, MAXBUF, fconf)) {
        if(strlen(lin) > 0 && lin[strlen(lin) - 1] == '\n')
            lin[strlen(lin) - 1] = '\0';
        if(!regexec(&Empty, lin, 4, matches, 0) || !regexec(&Comment, lin, 4, matches, 0)) {
            /* comment or empty line */
            continue;
        } else if(!regexec(&ListenHTTP, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            if((http[n_http++] = strdup(lin + matches[1].rm_so)) == NULL) {
                syslog(LOG_ERR, "ListenHTTP config: out of memory - aborted");
                exit(1);
            }
        } else if(!regexec(&ListenHTTPS, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = lin[matches[2].rm_eo] = '\0';
            if((https[n_https] = strdup(lin + matches[1].rm_so)) == NULL) {
                syslog(LOG_ERR, "ListenHTTPS config: out of memory - aborted");
                exit(1);
            }
            if((cert[n_https] = strdup(lin + matches[2].rm_so)) == NULL) {
                syslog(LOG_ERR, "ListenHTTPS CERT config: out of memory - aborted");
                exit(1);
            }
            if(matches[3].rm_so < matches[3].rm_eo) {
                lin[matches[3].rm_eo] = '\0';
                if((ciphers[n_https] = strdup(lin + matches[3].rm_so)) == NULL) {
                    syslog(LOG_ERR, "ListenHTTPS CIPHER config: out of memory - aborted");
                    exit(1);
                }
            } else
                ciphers[n_https] = NULL;
            n_https++;
        } else if(!regexec(&HTTPSHeadersOn, lin, 4, matches, 0)) {
            https_headers = 1;
        } else if(!regexec(&HTTPSHeaders, lin, 4, matches, 0)) {
            if(matches[1].rm_eo == matches[1].rm_so) {
                syslog(LOG_ERR, "HTTPSHeaders config: value may not be empty - aborted");
                exit(1);
            }
            https_headers = 1;
            lin[matches[1].rm_eo] = '\0';
            if((https_header = strdup(lin + matches[1].rm_so)) == NULL) {
                syslog(LOG_ERR, "HTTPSHeaders config: out of memory - aborted");
                exit(1);
            }
        } else if(!regexec(&User, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            if((user = strdup(lin + matches[1].rm_so)) == NULL) {
                syslog(LOG_ERR, "User config: out of memory - aborted");
                exit(1);
            }
        } else if(!regexec(&Group, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            if((group = strdup(lin + matches[1].rm_so)) == NULL) {
                syslog(LOG_ERR, "Group config: out of memory - aborted");
                exit(1);
            }
        } else if(!regexec(&RootJail, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            if((root = strdup(lin + matches[1].rm_so)) == NULL) {
                syslog(LOG_ERR, "RootJail config: out of memory - aborted");
                exit(1);
            }
        } else if(!regexec(&ExtendedHTTP, lin, 4, matches, 0)) {
            allow_xtd = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&WebDAV, lin, 4, matches, 0)) {
            allow_dav = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&LogLevel, lin, 4, matches, 0)) {
            log_level = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&Alive, lin, 4, matches, 0)) {
            alive_to = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&Client, lin, 4, matches, 0)) {
            clnt_to = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&UrlGroup, lin, 4, matches, 0)) {
            if(in_group) {
                syslog(LOG_ERR, "UrlGroup in UrlGroup - aborted");
                exit(1);
            }
            in_group = 1;
            if((groups[tot_groups] = (GROUP *)malloc(sizeof(GROUP))) == NULL) {
                syslog(LOG_ERR, "UrlGroup out of memory - aborted");
                exit(1);
            }
            lin[matches[1].rm_eo] = '\0';
            if(regcomp(&groups[tot_groups]->url_pat, lin + matches[1].rm_so, REG_ICASE | REG_EXTENDED | REG_NOSUB)) {
                syslog(LOG_ERR, "UrlGroup bad pattern \"%s\" - aborted", lin + matches[1].rm_so);
                exit(1);
            }
            pthread_mutex_init(&groups[tot_groups]->mut, NULL);
            groups[tot_groups]->sessions = NULL;
            groups[tot_groups]->tot_pri = 0;
            groups[tot_groups]->sess_type = SessNONE;
            groups[tot_groups]->sess_to = 300;
            tot_req = tot_deny = j = 0;
        } else if(in_group && !regexec(&BackEnd, lin, 4, matches, 0)) {
            memset(&addr, 0, sizeof(addr));
            memset(&alive_addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            lin[matches[1].rm_eo] = '\0';
            if((host = gethostbyname(lin + matches[1].rm_so)) == NULL) {
                syslog(LOG_ERR, "Unknown back-end host %s", lin + matches[1].rm_so);
                exit(1);
            }
            memcpy(&addr.sin_addr.s_addr, host->h_addr_list[0], sizeof(addr.sin_addr.s_addr));
            addr.sin_port = (in_port_t)htons(atoi(lin + matches[2].rm_so));
            for(k = atoi(lin + matches[3].rm_so); k > 0; k--, j++) {
                be[j].addr = addr;
                be[j].alive_addr = alive_addr;
                be[j].alive = 1;
            }
        } else if(in_group && !regexec(&BackEndHA, lin, 5, matches, 0)) {
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            memset(&alive_addr, 0, sizeof(addr));
            alive_addr.sin_family = AF_INET;
            lin[matches[1].rm_eo] = '\0';
            if((host = gethostbyname(lin + matches[1].rm_so)) == NULL) {
                syslog(LOG_ERR, "Unknown back-end host %s", lin + matches[1].rm_so);
                exit(1);
            }
            memcpy(&addr.sin_addr.s_addr, host->h_addr_list[0], sizeof(addr.sin_addr.s_addr));
            memcpy(&alive_addr.sin_addr.s_addr, host->h_addr_list[0], sizeof(alive_addr.sin_addr.s_addr));
            addr.sin_port = (in_port_t)htons(atoi(lin + matches[2].rm_so));
            alive_addr.sin_port = (in_port_t)htons(atoi(lin + matches[4].rm_so));
            for(k = atoi(lin + matches[3].rm_so); k > 0; k--, j++) {
                be[j].addr = addr;
                be[j].alive_addr = alive_addr;
                be[j].alive = 1;
            }
        } else if(in_group && !regexec(&SessionIP, lin, 4, matches, 0)) {
            if(groups[tot_groups]->sess_type != SessNONE) {
                syslog(LOG_ERR, "Multiple Session types defined in a Group - aborted");
                exit(1);
            }
            groups[tot_groups]->sess_type = SessIP;
            if((groups[tot_groups]->sess_to = atoi(lin + matches[1].rm_so)) < 0)
                syslog(LOG_NOTICE, "sticky session activated for group %d", tot_groups);
            else if(groups[tot_groups]->sess_to == 0)
                syslog(LOG_NOTICE, "session timeout 0 - no sessions kept for group %d", tot_groups);
        } else if(in_group && !regexec(&SessionURL, lin, 4, matches, 0)) {
            if(groups[tot_groups]->sess_type != SessNONE) {
                syslog(LOG_ERR, "Multiple Session types defined in a Group - aborted");
                exit(1);
            }
            groups[tot_groups]->sess_type = SessURL;
            lin[matches[1].rm_eo] = '\0';
            sprintf(pat, "[?&]%s=([^&]*)", lin + matches[1].rm_so);
            if(regcomp(&groups[tot_groups]->sess_pat, pat, REG_ICASE | REG_EXTENDED)) {
                syslog(LOG_ERR, "Session URL bad pattern \"%s\" - aborted", pat);
                exit(1);
            }
            if((groups[tot_groups]->sess_to = atoi(lin + matches[2].rm_so)) < 0)
                syslog(LOG_ERR, "no sticky session for Session URL - aborted");
        } else if(in_group && !regexec(&SessionCOOKIE, lin, 4, matches, 0)) {
            if(groups[tot_groups]->sess_type != SessNONE) {
                syslog(LOG_ERR, "Multiple Session types defined in a Group - aborted");
                exit(1);
            }
            groups[tot_groups]->sess_type = SessCOOKIE;
            lin[matches[1].rm_eo] = '\0';
            /* this matches Cookie: ... as well as Set-cookie: ... */
            sprintf(pat, "Cookie:.*[ \t]%s=([^;]*)", lin + matches[1].rm_so);
            if(regcomp(&groups[tot_groups]->sess_pat, pat, REG_ICASE | REG_EXTENDED)) {
                syslog(LOG_ERR, "Session URL bad pattern \"%s\" - aborted", pat);
                exit(1);
            }
            if((groups[tot_groups]->sess_to = atoi(lin + matches[2].rm_so)) < 0)
                syslog(LOG_ERR, "no sticky session for Session URL - aborted");
        } else if(in_group && !regexec(&HeadRequire, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = lin[matches[2].rm_eo] = '\0';
            sprintf(pat, "^%s: *%s$", lin + matches[1].rm_so, lin + matches[2].rm_so);
            if(regcomp(&req[tot_req++], pat, REG_ICASE | REG_NEWLINE | REG_EXTENDED)) {
                syslog(LOG_ERR, "HeadRequire %s bad pattern \"%s\" - aborted",
                    lin + matches[1].rm_so, lin + matches[2].rm_so);
                exit(1);
            }
        } else if(in_group && !regexec(&HeadDeny, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = lin[matches[2].rm_eo] = '\0';
            sprintf(pat, "^%s: *%s$", lin + matches[1].rm_so, lin + matches[2].rm_so);
            if(regcomp(&deny[tot_deny++], pat, REG_ICASE | REG_NEWLINE | REG_EXTENDED)) {
                syslog(LOG_ERR, "HeadDeny %s bad pattern \"%s\" - aborted",
                    lin + matches[1].rm_so, lin + matches[2].rm_so);
                exit(1);
            }
        } else if(in_group && !regexec(&EndGroup, lin, 4, matches, 0)) {
            if((groups[tot_groups]->backend_addr = malloc(sizeof(BACKEND) * j)) == NULL) {
                syslog(LOG_ERR, "EndGroup out of memory - aborted");
                exit(1);
            }
            for(k = 0; k < j; k++)
                groups[tot_groups]->backend_addr[k] = be[k];
            groups[tot_groups]->tot_pri = j;

            if((groups[tot_groups]->n_req = tot_req) > 0) {
                if((groups[tot_groups]->head_req = (regex_t *)malloc(sizeof(regex_t) * tot_req)) == NULL) {
                    syslog(LOG_ERR, "EndGroup head_req out of memory - aborted");
                    exit(1);
                }
                while(--tot_req >= 0)
                    groups[tot_groups]->head_req[tot_req] = req[tot_req];
            } else
                groups[tot_groups]->head_req = NULL;

            if((groups[tot_groups]->n_deny = tot_deny) > 0) {
                if((groups[tot_groups]->head_deny = (regex_t *)malloc(sizeof(regex_t) * tot_deny)) == NULL) {
                    syslog(LOG_ERR, "EndGroup head_deny out of memory - aborted");
                    exit(1);
                }
                while(--tot_deny >= 0)
                    groups[tot_groups]->head_deny[tot_deny] = deny[tot_deny];
            } else
                groups[tot_groups]->head_deny = NULL;

            tot_groups++;
            in_group = 0;
        } else {
            syslog(LOG_ERR, "unknown directive \"%s\" - aborted", lin);
            exit(1);
        }
    }

    fclose(fconf);
    free(be);
    if(req)
        free(req);
    if(deny)
        free(deny);
    regfree(&Empty);
    regfree(&Comment);
    regfree(&ListenHTTP);
    regfree(&ListenHTTPS);
    regfree(&HTTPSHeaders);
    regfree(&HTTPSHeadersOn);
    regfree(&SessionIP);
    regfree(&SessionURL);
    regfree(&SessionCOOKIE);
    regfree(&User);
    regfree(&Group);
    regfree(&RootJail);
    regfree(&ExtendedHTTP);
    regfree(&WebDAV);
    regfree(&LogLevel);
    regfree(&Alive);
    regfree(&Client);
    regfree(&UrlGroup);
    regfree(&BackEnd);
    regfree(&BackEndHA);
    regfree(&EndGroup);
    return;
}

/*
 * parse the arguments/config file
 */
void
config_parse(int argc, char **argv)
{
    /* init values */
    clnt_to = 10;
    log_level = 1;
    https_headers = 0;
    https_header = NULL;
    allow_xtd = 0;
    allow_dav = 0;
    alive_to = 30;
    http = NULL;
    https = NULL;
    cert = NULL;
    user = NULL;
    groups = NULL;
    root = NULL;

    if(argc == 1) {
        /* without arguments - use default configuration file */
#ifndef F_CONF
#define F_CONF  "/etc/pound/pound.cfg"
#endif
        parse_file(F_CONF);
    } else if(argc == 3 && !strcmp(argv[1], "-f")) {
        /* argument is the configuration file */
        parse_file(argv[2]);
    } else {
        syslog(LOG_ERR, "bad argument(s)");
        exit(1);
    }

    if(!http[0] && !https[0]) {
        syslog(LOG_ERR, "no HTTP and no HTTPS - aborted");
        exit(1);
    }
    if(user || group || root)
        if(geteuid()) {
            syslog(LOG_ERR, "must be started as root - aborted");
            exit(1);
        }
    if(groups[0] == NULL) {
        syslog(LOG_ERR, "no backend group(s) given - aborted");
        exit(1);
    }

    return;
}
