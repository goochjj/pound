/*
 * Pound - the reverse-proxy load-balancer
 * Copyright (C) 2002-2006 Apsis GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * Additionaly compiling, linking, and/or using OpenSSL is expressly allowed.
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
 * Tel: +41-44-920 4904
 * EMail: roseg@apsis.ch
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
            print_log,          /* print log messages to stdout/stderr */
            control_sock;       /* control socket */

SERVICE     *services;          /* global services (if any) */

LISTENER    *listeners;         /* all available listeners */

regex_t HEADER,             /* Allowed header */
        CHUNK_HEAD,         /* chunk header line */
        RESP_SKIP,          /* responses for which we skip response */
        RESP_IGN,           /* responses for which we ignore content */
        /* RESP_REDIR,         /* responses for which we rewrite Location */
        LOCATION,           /* the host we are redirected to */
        AUTHORIZATION;      /* the Authorisation header */

#ifndef  SOL_TCP
/* for systems without the definition */
int     SOL_TCP;
#endif

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
        /* pthread_mutex_init() always returns 0 */
        pthread_mutex_init(&l_array[i], NULL);
    return;
}

static void
l_lock(const int mode, const int n, /* unused */ const char *file, /* unused */ int line)
{
    int ret_val;

    if(mode & CRYPTO_LOCK) {
        if(ret_val = pthread_mutex_lock(&l_array[n]))
            logmsg(LOG_ERR, "l_lock lock(): %s", strerror(ret_val));
    } else {
        if(ret_val = pthread_mutex_unlock(&l_array[n]))
            logmsg(LOG_ERR, "l_lock unlock(): %s", strerror(ret_val));
    }
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
h_term(const int sig)
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
main(const int argc, char **argv)
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
    char                tmp[MAXBUF];
#ifndef SOL_TCP
    struct protoent     *pe;
#endif

    print_log = 0;
    (void)umask(077);
    control_sock = -1;
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
    init_host_mut();
    init_RSAgen();

    /* prepare regular expressions */
    if(regcomp(&HEADER, "^([a-z0-9!#$%&'*+.^_`|~-]+):[ \t]*(.*)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&CHUNK_HEAD, "^([0-9a-f]+).*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&RESP_SKIP, "^HTTP/1.1 100.*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&RESP_IGN, "^HTTP/1.[01] (10[1-9]|1[1-9][0-9]|204|30[456]).*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    /* || regcomp(&RESP_REDIR, "^HTTP/1.[01] 30[1237].*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED) */
    || regcomp(&LOCATION, "(http|https)://([^/]+)(.*)", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&AUTHORIZATION, "Authorization:[ \t]*Basic[ \t]*([^ \t]*)[ \t]*", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    ) {
        logmsg(LOG_ERR, "bad essential Regex - aborted");
        exit(1);
    }

#ifndef SOL_TCP
    /* for systems without the definition */
    if((pe = getprotobyname("tcp")) == NULL) {
        logmsg(LOG_ERR, "missing TCP protocol");
        exit(1);
    }
    SOL_TCP = pe->p_proto;
#endif

    /* read config */
    config_parse(argc, argv);

    /* open HTTP listeners */
    for(lstn = listeners, n_listeners = 0; lstn; lstn = lstn->next, n_listeners++) {
        int opt;

        /* prepare the socket */
        if((lstn->sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
            addr2str(tmp, MAXBUF - 1, &lstn->addr.sin_addr);
            logmsg(LOG_ERR, "HTTP socket %s:%hd create: %s - aborted",
                tmp, ntohs(lstn->addr.sin_port), strerror(errno));
            exit(1);
        }
        opt = 1;
        setsockopt(lstn->sock, SOL_SOCKET, SO_REUSEADDR, (void *)&opt, sizeof(opt));
        if(bind(lstn->sock, (struct sockaddr *)&lstn->addr, (socklen_t)sizeof(lstn->addr)) < 0) {
            addr2str(tmp, MAXBUF - 1, &lstn->addr.sin_addr);
            logmsg(LOG_ERR, "HTTP socket bind %s:%hd: %s - aborted",
                tmp, ntohs(lstn->addr.sin_port), strerror(errno));
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
        logmsg(LOG_NOTICE, "Create \"%s\": %s", pid_name, strerror(errno));

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

            /* start the controlling thread (if needed) */
            if(control_sock >= 0 && pthread_create(&thr, &attr, thr_control, NULL)) {
                logmsg(LOG_ERR, "create thr_control: %s - aborted", strerror(errno));
                exit(1);
            }

            /* pause to make sure the service threads were started */
            sleep(2);

            /* and start working */
            for(;;) {
                for(lstn = listeners, i = 0; i < n_listeners; lstn = lstn->next, i++) {
                    if(lstn->disabled)
                        polls[i].events = 0;
                    else
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
