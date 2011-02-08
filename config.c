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

static char *rcs_id = "$Id: config.c,v 1.9 2005/06/01 15:01:53 roseg Rel $";

/*
 * $Log: config.c,v $
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

#include    "pound.h"

static char *
file2str(char *fname)
{
    char    *res;
    struct stat st;
    int     fin;

    if(stat(fname, &st)) {
        logmsg(LOG_ERR, "can't stat Err50x file \"%s\" (%s) - aborted", fname, strerror(errno));
        exit(1);
    }
    if((fin = open(fname, O_RDONLY)) < 0) {
        logmsg(LOG_ERR, "can't open Err50x file \"%s\" (%s) - aborted", fname, strerror(errno));
        exit(1);
    }
    if((res = malloc(st.st_size + 1)) == NULL) {
        logmsg(LOG_ERR, "can't alloc Err50x file \"%s\" (out of memory) - aborted", fname);
        exit(1);
    }
    if(read(fin, res, st.st_size) != st.st_size) {
        logmsg(LOG_ERR, "can't read Err50x file \"%s\" (%s) - aborted", fname, strerror(errno));
        exit(1);
    }
    res[st.st_size] = '\0';
    close(fin);
    return res;
}

static void
parse_file(char *fname)
{
    FILE                *fconf;
    char                lin[MAXBUF], pat[MAXBUF];
    regex_t             Empty, Comment, ListenHTTP, ListenHTTPS, HTTPSHeaders, MaxRequest, HeadRemove,
                        SSL_CAlist, SSLEngine, SessionIP, SessionURL, SessionCOOKIE, SessionBASIC, NO11SSL,
                        SSL_Verifylist, User, Group, RootJail, ExtendedHTTP, WebDAV, LogLevel, Alive, Server,
                        Client, UrlGroup, HeadRequire, HeadDeny, BackEnd, BackEndHA, EndGroup,
                        Err500, Err501, Err503, Err414, CheckURL, CS_SEGMENT, CS_PARM, CS_QID, CS_QVAL, CS_FRAG,
                        RewriteRedir;
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
    || regcomp(&HTTPSHeaders, "^[ \t]*HTTPSHeaders[ \t]+([0123])[ \t]+\"([^\"]*)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&SSL_CAlist, "^[ \t]*CAlist[ \t]+([^ \t]+)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&SSL_Verifylist, "^[ \t]*VerifyList[ \t]+([^ \t]+)[ \t]+([0-9])[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
#if HAVE_OPENSSL_ENGINE_H
    || regcomp(&SSLEngine, "^[ \t]*SSLEngine[ \t]+([^ \t]+)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
#endif
    || regcomp(&SessionIP, "^[ \t]*Session[ \t]+IP[ \t]+([0-9-][0-9]*)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&SessionURL, "^[ \t]*Session[ \t]+URL[ \t]+([^ \t]+)[ \t]+([0-9-][0-9]*)[ \t]*$",
        REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&SessionCOOKIE, "^[ \t]*Session[ \t]+Cookie[ \t]+([^ \t]+)[ \t]+([0-9-][0-9]*)[ \t]*$",
        REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&SessionBASIC, "^[ \t]*Session[ \t]+Basic[ \t]+([0-9-][0-9]*)[ \t]*$",
        REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&User, "^[ \t]*User[ \t]+([^ \t]+)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Group, "^[ \t]*Group[ \t]+([^ \t]+)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&RootJail, "^[ \t]*RootJail[ \t]+([^ \t]+)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&ExtendedHTTP, "^[ \t]*ExtendedHTTP[ \t]+([01])[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&WebDAV, "^[ \t]*WebDAV[ \t]+([01])[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&NO11SSL, "^[ \t]*NoHTTPS11[ \t]+([012])[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&LogLevel, "^[ \t]*LogLevel[ \t]+([01234])[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Alive, "^[ \t]*Alive[ \t]+([1-9][0-9]*)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Client, "^[ \t]*Client[ \t]+([1-9][0-9]*)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Server, "^[ \t]*Server[ \t]+([0-9]+)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&HeadRemove, "^[ \t]*HeadRemove[ \t]+\"([^\"]+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&UrlGroup, "^[ \t]*UrlGroup[ \t]+\"([^\"]+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&BackEnd, "^[ \t]*BackEnd[ \t]+([^,]+),([0-9]+),([1-9])[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&BackEndHA, "^[ \t]*BackEnd[ \t]+([^,]+),([0-9]+),([1-9]),([0-9]+)[ \t]*$",
        REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&HeadRequire, "^[ \t]*HeadRequire[ \t]+([^ \t]+)[ \t]+\"([^\"]+)\"[ \t]*$",
        REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&HeadDeny, "^[ \t]*HeadDeny[ \t]+([^ \t]+)[ \t]+\"([^\"]+)\"[ \t]*$",
        REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&EndGroup, "^[ \t]*EndGroup[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Err500, "^[ \t]*Err500[ \t]+\"([^\"]+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Err501, "^[ \t]*Err501[ \t]+\"([^\"]+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Err503, "^[ \t]*Err503[ \t]+\"([^\"]+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&Err414, "^[ \t]*Err414[ \t]+\"([^\"]+)\"[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&CheckURL, "^[ \t]*CheckURL[ \t]+([01])[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&CS_SEGMENT, "^[ \t]*CSsegment[ \t]+([^ ]+)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&CS_PARM, "^[ \t]*CSparameter[ \t]+([^ ]+)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&CS_QID, "^[ \t]*CSqid[ \t]+([^ ]+)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&CS_QVAL, "^[ \t]*CSqval[ \t]+([^ ]+)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&CS_FRAG, "^[ \t]*CSfragment[ \t]+([^ ]+)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&MaxRequest, "^[ \t]*MaxRequest[ \t]+([1-9][0-9]*)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&RewriteRedir, "^[ \t]*RewriteRedirect[ \t]+([0-2])[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    ) {
        logmsg(LOG_ERR, "bad config Regex - aborted");
        exit(1);
    }

    if((fconf = fopen(fname, "rt")) == NULL) {
        logmsg(LOG_ERR, "can't open configuration file \"%s\" (%s) - aborted", fname, strerror(errno));
        exit(1);
    }

    /* first pass - just find number of groups and backends so we can allocate correctly */
    for(n_http = n_https = tot_be = tot_groups = n_head_off = tot_req = tot_deny = 0; fgets(lin, MAXBUF, fconf); ) {
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
        else if(!regexec(&HeadRemove, lin, 4, matches, 0))
            n_head_off++;
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
        logmsg(LOG_ERR, "listen setup: out of memory - aborted");
        exit(1);
    }
    http[n_http] = https[n_https] = cert[n_https] = NULL;

    if((groups = (GROUP **)malloc(sizeof(GROUP *) * (tot_groups + 1))) == NULL) {
        logmsg(LOG_ERR, "groups setup: out of memory - aborted");
        exit(1);
    }
    groups[tot_groups] = NULL;

    if((be = (BACKEND *)malloc(sizeof(BACKEND) * tot_be)) == NULL) {
        logmsg(LOG_ERR, "backend setup: out of memory - aborted");
        exit(1);
    }
    if(tot_req > 0) {
        if((req = (regex_t *)malloc(sizeof(regex_t) * tot_req)) == NULL) {
            logmsg(LOG_ERR, "req setup: out of memory - aborted");
            exit(1);
        }
    } else
        req = NULL;
    if(tot_deny > 0) {
        if((deny = (regex_t *)malloc(sizeof(regex_t) * tot_deny)) == NULL) {
            logmsg(LOG_ERR, "deny setup: out of memory - aborted");
            exit(1);
        }
    } else
        deny = NULL;
    if(n_head_off > 0 && (head_off = (regex_t *)malloc(sizeof(regex_t) * n_head_off)) == NULL) {
        logmsg(LOG_ERR, "HeadRemove setup: out of memory - aborted");
        exit(1);
    }
    n_head_off = 0;

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
                logmsg(LOG_ERR, "ListenHTTP config: out of memory - aborted");
                exit(1);
            }
        } else if(!regexec(&ListenHTTPS, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = lin[matches[2].rm_eo] = '\0';
            if((https[n_https] = strdup(lin + matches[1].rm_so)) == NULL) {
                logmsg(LOG_ERR, "ListenHTTPS config: out of memory - aborted");
                exit(1);
            }
            if((cert[n_https] = strdup(lin + matches[2].rm_so)) == NULL) {
                logmsg(LOG_ERR, "ListenHTTPS CERT config: out of memory - aborted");
                exit(1);
            }
            if(matches[3].rm_so < matches[3].rm_eo) {
                lin[matches[3].rm_eo] = '\0';
                if((ciphers[n_https] = strdup(lin + matches[3].rm_so)) == NULL) {
                    logmsg(LOG_ERR, "ListenHTTPS CIPHER config: out of memory - aborted");
                    exit(1);
                }
            } else
                ciphers[n_https] = NULL;
            n_https++;
#if HAVE_OPENSSL_ENGINE_H
        } else if(!regexec(&SSLEngine, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            if((ssl_engine = strdup(lin + matches[1].rm_so)) == NULL) {
                logmsg(LOG_ERR, "SSLEngine config: out of memory - aborted");
                exit(1);
            }
#endif
        } else if(!regexec(&HTTPSHeaders, lin, 4, matches, 0)) {
            https_headers = atoi(lin + matches[1].rm_so);
            if(matches[2].rm_eo != matches[2].rm_so) {
                lin[matches[2].rm_eo] = '\0';
                if((https_header = strdup(lin + matches[2].rm_so)) == NULL) {
                    logmsg(LOG_ERR, "HTTPSHeaders config: out of memory - aborted");
                    exit(1);
                }
            } else
                https_header = NULL;
        } else if(!regexec(&SSL_CAlist, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            if((ssl_CAlst = strdup(lin + matches[1].rm_so)) == NULL) {
                logmsg(LOG_ERR, "CAlist config: out of memory - aborted");
                exit(1);
            }
        } else if(!regexec(&SSL_Verifylist, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            if((ssl_Verifylst = strdup(lin + matches[1].rm_so)) == NULL) {
                logmsg(LOG_ERR, "Verifylist config: out of memory - aborted");
                exit(1);
            }
            ssl_vdepth = atoi(lin + matches[2].rm_so);
        } else if(!regexec(&Err500, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            e500 = file2str(lin + matches[1].rm_so);
        } else if(!regexec(&Err501, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            e501 = file2str(lin + matches[1].rm_so);
        } else if(!regexec(&Err503, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            e503 = file2str(lin + matches[1].rm_so);
        } else if(!regexec(&Err414, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            e414 = file2str(lin + matches[1].rm_so);
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
            if((root = strdup(lin + matches[1].rm_so)) == NULL) {
                logmsg(LOG_ERR, "RootJail config: out of memory - aborted");
                exit(1);
            }
        } else if(!regexec(&CS_SEGMENT, lin, 4, matches, 0)) {
            if(CS_segment != NULL) {
                logmsg(LOG_ERR, "CSsegment config: multiple definition - aborted");
                exit(1);
            }
            lin[matches[1].rm_eo] = '\0';
            if((CS_segment = strdup(lin + matches[1].rm_so)) == NULL) {
                logmsg(LOG_ERR, "CSsegment config: out of memory - aborted");
                exit(1);
            }
        } else if(!regexec(&CS_PARM, lin, 4, matches, 0)) {
            if(CS_parm != NULL) {
                logmsg(LOG_ERR, "CSparameter config: multiple definition - aborted");
                exit(1);
            }
            lin[matches[1].rm_eo] = '\0';
            if((CS_parm = strdup(lin + matches[1].rm_so)) == NULL) {
                logmsg(LOG_ERR, "CSparameter config: out of memory - aborted");
                exit(1);
            }
        } else if(!regexec(&CS_QID, lin, 4, matches, 0)) {
            if(CS_qid != NULL) {
                logmsg(LOG_ERR, "CSqid config: multiple definition - aborted");
                exit(1);
            }
            lin[matches[1].rm_eo] = '\0';
            if((CS_qid = strdup(lin + matches[1].rm_so)) == NULL) {
                logmsg(LOG_ERR, "CSqid config: out of memory - aborted");
                exit(1);
            }
        } else if(!regexec(&CS_QVAL, lin, 4, matches, 0)) {
            if(CS_qval != NULL) {
                logmsg(LOG_ERR, "CSqval config: multiple definition - aborted");
                exit(1);
            }
            lin[matches[1].rm_eo] = '\0';
            if((CS_qval = strdup(lin + matches[1].rm_so)) == NULL) {
                logmsg(LOG_ERR, "CSqval config: out of memory - aborted");
                exit(1);
            }
        } else if(!regexec(&CS_FRAG, lin, 4, matches, 0)) {
            if(CS_frag != NULL) {
                logmsg(LOG_ERR, "CSfragment config: multiple definition - aborted");
                exit(1);
            }
            lin[matches[1].rm_eo] = '\0';
            if((CS_frag = strdup(lin + matches[1].rm_so)) == NULL) {
                logmsg(LOG_ERR, "CSfragment config: out of memory - aborted");
                exit(1);
            }
        } else if(!regexec(&HeadRemove, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = '\0';
            snprintf(pat, MAXBUF - 1, "%s:.*", lin + matches[1].rm_so);
            if(regcomp(&head_off[n_head_off++], pat, REG_ICASE | REG_EXTENDED)) {
                logmsg(LOG_ERR, "HeadRemove bad pattern \"%s\" - aborted", pat);
                exit(1);
            }
        } else if(!regexec(&ExtendedHTTP, lin, 4, matches, 0)) {
            allow_xtd = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&WebDAV, lin, 4, matches, 0)) {
            allow_dav = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&NO11SSL, lin, 4, matches, 0)) {
            no_https_11 = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&LogLevel, lin, 4, matches, 0)) {
            log_level = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&Alive, lin, 4, matches, 0)) {
            alive_to = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&Client, lin, 4, matches, 0)) {
            clnt_to = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&Server, lin, 4, matches, 0)) {
            server_to = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&MaxRequest, lin, 4, matches, 0)) {
            max_req = atol(lin + matches[1].rm_so);
        } else if(!regexec(&CheckURL, lin, 4, matches, 0)) {
            check_URL = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&RewriteRedir, lin, 4, matches, 0)) {
            rewrite_redir = atoi(lin + matches[1].rm_so);
        } else if(!regexec(&UrlGroup, lin, 4, matches, 0)) {
            if(in_group) {
                logmsg(LOG_ERR, "UrlGroup in UrlGroup - aborted");
                exit(1);
            }
            in_group = 1;
            if((groups[tot_groups] = (GROUP *)malloc(sizeof(GROUP))) == NULL) {
                logmsg(LOG_ERR, "UrlGroup out of memory - aborted");
                exit(1);
            }
            lin[matches[1].rm_eo] = '\0';
            if(regcomp(&groups[tot_groups]->url_pat, lin + matches[1].rm_so, REG_ICASE | REG_EXTENDED | REG_NOSUB)) {
                logmsg(LOG_ERR, "UrlGroup bad pattern \"%s\" - aborted", lin + matches[1].rm_so);
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
                logmsg(LOG_ERR, "Unknown back-end host \"%s\"", lin + matches[1].rm_so);
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
                logmsg(LOG_ERR, "Unknown back-end host \"%s\"", lin + matches[1].rm_so);
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
                logmsg(LOG_ERR, "Multiple Session types defined in a Group - aborted");
                exit(1);
            }
            groups[tot_groups]->sess_type = SessIP;
            if((groups[tot_groups]->sess_to = atoi(lin + matches[1].rm_so)) < 0)
                logmsg(LOG_NOTICE, "sticky session activated for group %d", tot_groups);
            else if(groups[tot_groups]->sess_to == 0)
                logmsg(LOG_NOTICE, "session timeout 0 - no sessions kept for group %d", tot_groups);
        } else if(in_group && !regexec(&SessionBASIC, lin, 4, matches, 0)) {
            if(groups[tot_groups]->sess_type != SessNONE) {
                logmsg(LOG_ERR, "Multiple Session types defined in a Group - aborted");
                exit(1);
            }
            groups[tot_groups]->sess_type = SessBASIC;
            if((groups[tot_groups]->sess_to = atoi(lin + matches[1].rm_so)) < 0)
                logmsg(LOG_NOTICE, "sticky session activated for group %d", tot_groups);
            else if(groups[tot_groups]->sess_to == 0)
                logmsg(LOG_NOTICE, "session timeout 0 - no sessions kept for group %d", tot_groups);
            snprintf(pat, MAXBUF - 1, "Authorization:[ \t]*Basic[ \t]*([^ \t]*)[ \t]*");
            if(regcomp(&groups[tot_groups]->sess_pat, pat, REG_ICASE | REG_EXTENDED)) {
                logmsg(LOG_ERR, "Session Basic bad pattern \"%s\" - aborted", pat);
                exit(1);
            }
        } else if(in_group && !regexec(&SessionURL, lin, 4, matches, 0)) {
            if(groups[tot_groups]->sess_type != SessNONE) {
                logmsg(LOG_ERR, "Multiple Session types defined in a Group - aborted");
                exit(1);
            }
            groups[tot_groups]->sess_type = SessURL;
            lin[matches[1].rm_eo] = '\0';
            snprintf(pat, MAXBUF - 1, "[?&]%s=([^&]*)", lin + matches[1].rm_so);
            if(regcomp(&groups[tot_groups]->sess_pat, pat, REG_ICASE | REG_EXTENDED)) {
                logmsg(LOG_ERR, "Session URL bad pattern \"%s\" - aborted", pat);
                exit(1);
            }
            if((groups[tot_groups]->sess_to = atoi(lin + matches[2].rm_so)) <= 0)
                logmsg(LOG_ERR, "no sticky session for Session URL - aborted");
        } else if(in_group && !regexec(&SessionCOOKIE, lin, 4, matches, 0)) {
            if(groups[tot_groups]->sess_type != SessNONE) {
                logmsg(LOG_ERR, "Multiple Session types defined in a Group - aborted");
                exit(1);
            }
            groups[tot_groups]->sess_type = SessCOOKIE;
            lin[matches[1].rm_eo] = '\0';
            /* this matches Cookie: ... as well as Set-cookie: ... */
            snprintf(pat, MAXBUF - 1, "Cookie:.*[ \t]%s=([^;]*)", lin + matches[1].rm_so);
            if(regcomp(&groups[tot_groups]->sess_pat, pat, REG_ICASE | REG_EXTENDED)) {
                logmsg(LOG_ERR, "Session Cookie bad pattern \"%s\" - aborted", pat);
                exit(1);
            }
            if((groups[tot_groups]->sess_to = atoi(lin + matches[2].rm_so)) <= 0)
                logmsg(LOG_ERR, "no sticky session for Session Cookie - aborted");
        } else if(in_group && !regexec(&HeadRequire, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = lin[matches[2].rm_eo] = '\0';
            snprintf(pat, MAXBUF - 1, "^%s: *%s$", lin + matches[1].rm_so, lin + matches[2].rm_so);
            if(regcomp(&req[tot_req++], pat, REG_ICASE | REG_NEWLINE | REG_EXTENDED)) {
                logmsg(LOG_ERR, "HeadRequire %s bad pattern \"%s\" - aborted",
                    lin + matches[1].rm_so, lin + matches[2].rm_so);
                exit(1);
            }
        } else if(in_group && !regexec(&HeadDeny, lin, 4, matches, 0)) {
            lin[matches[1].rm_eo] = lin[matches[2].rm_eo] = '\0';
            snprintf(pat, MAXBUF - 1, "^%s: *%s$", lin + matches[1].rm_so, lin + matches[2].rm_so);
            if(regcomp(&deny[tot_deny++], pat, REG_ICASE | REG_NEWLINE | REG_EXTENDED)) {
                logmsg(LOG_ERR, "HeadDeny %s bad pattern \"%s\" - aborted",
                    lin + matches[1].rm_so, lin + matches[2].rm_so);
                exit(1);
            }
        } else if(in_group && !regexec(&EndGroup, lin, 4, matches, 0)) {
            if((groups[tot_groups]->backend_addr = malloc(sizeof(BACKEND) * j)) == NULL) {
                logmsg(LOG_ERR, "EndGroup out of memory - aborted");
                exit(1);
            }
            for(k = 0; k < j; k++)
                groups[tot_groups]->backend_addr[k] = be[k];
            groups[tot_groups]->tot_pri = j;

            if((groups[tot_groups]->n_req = tot_req) > 0) {
                if((groups[tot_groups]->head_req = (regex_t *)malloc(sizeof(regex_t) * tot_req)) == NULL) {
                    logmsg(LOG_ERR, "EndGroup head_req out of memory - aborted");
                    exit(1);
                }
                while(--tot_req >= 0)
                    groups[tot_groups]->head_req[tot_req] = req[tot_req];
            } else
                groups[tot_groups]->head_req = NULL;

            if((groups[tot_groups]->n_deny = tot_deny) > 0) {
                if((groups[tot_groups]->head_deny = (regex_t *)malloc(sizeof(regex_t) * tot_deny)) == NULL) {
                    logmsg(LOG_ERR, "EndGroup head_deny out of memory - aborted");
                    exit(1);
                }
                while(--tot_deny >= 0)
                    groups[tot_groups]->head_deny[tot_deny] = deny[tot_deny];
            } else
                groups[tot_groups]->head_deny = NULL;

            tot_groups++;
            in_group = 0;
        } else {
            logmsg(LOG_ERR, "unknown directive \"%s\" - aborted", lin);
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
    regfree(&SSL_CAlist);
    regfree(&SSL_Verifylist);
#if HAVE_OPENSSL_ENGINE_H
    regfree(&SSLEngine);
#endif
    regfree(&SessionIP);
    regfree(&SessionURL);
    regfree(&SessionCOOKIE);
    regfree(&SessionBASIC);
    regfree(&User);
    regfree(&Group);
    regfree(&RootJail);
    regfree(&ExtendedHTTP);
    regfree(&WebDAV);
    regfree(&NO11SSL);
    regfree(&LogLevel);
    regfree(&Alive);
    regfree(&Client);
    regfree(&Server);
    regfree(&UrlGroup);
    regfree(&BackEnd);
    regfree(&BackEndHA);
    regfree(&EndGroup);
    regfree(&Err500);
    regfree(&Err501);
    regfree(&Err503);
    regfree(&Err414);
    regfree(&CheckURL);
    regfree(&CS_SEGMENT);
    regfree(&CS_PARM);
    regfree(&CS_QID);
    regfree(&CS_QVAL);
    regfree(&CS_FRAG);
    regfree(&MaxRequest);
    regfree(&HeadRemove);
    regfree(&HeadRequire);
    regfree(&HeadDeny);
    regfree(&RewriteRedir);
    return;
}

extern char *optarg;
extern int  optind, opterr, optopt;

/*
 * parse the arguments/config file
 */
void
config_parse(int argc, char **argv)
{
    int c_opt, check_only;
    char    *conf_name;

    /* init values */
    clnt_to = 10;
    server_to = 0;
    log_level = 1;
    https_headers = 0;
    https_header = NULL;
    ssl_CAlst = NULL;
    ssl_Verifylst = NULL;
    ssl_vdepth = 1;
    allow_xtd = 0;
    allow_dav = 0;
    no_https_11 = 2;
    alive_to = 30;
    max_req = 0L;
    http = NULL;
    https = NULL;
    cert = NULL;
#if HAVE_OPENSSL_ENGINE_H
    ssl_engine = NULL;
#endif
    user = NULL;
    groups = NULL;
    root = NULL;
    e500 = e501 = e503 = e414 = NULL;
    CS_segment = CS_parm = CS_qid = CS_qval = CS_frag = NULL;
    head_off = NULL;
    check_URL = 0;
    rewrite_redir = 1;

    opterr = 0;
    check_only = 0;
    conf_name = F_CONF;
    pid_name = F_PID;

    while((c_opt = getopt(argc, argv, "f:cvp:")) > 0)
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
        default:
            logmsg(LOG_ERR, "bad flag -%c", optopt);
            exit(1);
        }
    if(optind < argc) {
        logmsg(LOG_ERR, "unknown extra arguments (%s...)", argv[optind]);
        exit(1);
    }

    parse_file(conf_name);
    if(check_only) {
        logmsg(LOG_INFO, "Config file %s is OK", conf_name);
        exit(0);
    }

    if(!http[0] && !https[0]) {
        logmsg(LOG_ERR, "no HTTP and no HTTPS - aborted");
        exit(1);
    }
    if(user || group || root)
        if(geteuid()) {
            logmsg(LOG_ERR, "must be started as root - aborted");
            exit(1);
        }
    if(groups[0] == NULL) {
        logmsg(LOG_ERR, "no backend group(s) given - aborted");
        exit(1);
    }
    if(e500 == NULL)
        e500 = "An internal server error occurred. Please try again later.";
    if(e501 == NULL)
        e501 = "This method may not be used.";
    if(e503 == NULL)
        e503 = "The service is not available. Please try again later.";
    if(e414 == NULL)
        e414 = "Request URI is too long";

#ifdef  UNSAFE
    if(CS_segment == NULL)
#ifdef  MSDAV
        CS_segment = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.!~*'():@&=+$,%-{}<>\"|\\^[]'";
#else
        CS_segment = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.!~*'():@&=+$,%-{}|\\^[]'";
#endif
    if(CS_parm == NULL)
        CS_parm = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.!~*'():@&=+$,%-{}|\\^[]'";
    if(CS_qid == NULL)
        CS_qid = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.!~*'(),%-{}|\\^[]'";
    if(CS_qval == NULL)
        CS_qval = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/_.!~*'(),%-{}|\\^[]'+";
    if(CS_frag == NULL)
        CS_frag = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.!~*'(),%{}|\\^[]'";
#else
    if(CS_segment == NULL)
#ifdef  MSDAV
        CS_segment = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.!~*'():@&=+$,%-{}<>\"";
#else
        CS_segment = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.!~*'():@&=+$,%-";
#endif
    if(CS_parm == NULL)
        CS_parm = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.!~*'():@&=+$,%-";
    if(CS_qid == NULL)
        CS_qid = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.!~*'(),%-";
    if(CS_qval == NULL)
        CS_qval = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/_.!~*'(),%-+";
    if(CS_frag == NULL)
        CS_frag = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.!~*'(),%-";
#endif

    return;
}
