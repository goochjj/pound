#define NO_EXTERNALS 1
#include    "pound.h"

static void
usage(const char *arg0)
{
    fprintf(stderr, "Usage: %s -c /control/socket cmd\n", arg0);
    fprintf(stderr, "\twhere cmd is one of:\n");
    fprintf(stderr, "\t-L n - enable listener n\n");
    fprintf(stderr, "\t-l n - disable listener n\n");
    fprintf(stderr, "\t-S n m - enable service m in service n (use -1 for global services)\n");
    fprintf(stderr, "\t-s n m - disable service m in service n (use -1 for global services)\n");
    fprintf(stderr, "\t-B n m r - enable back-end in service m in listener n\n");
    fprintf(stderr, "\t-b n m r - disable back-end in service m in listener n\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "\tentering the command without arguments lists the current configuration.\n");
    exit(1);
}

static int
get_sock(const char *sock_name)
{
    struct sockaddr_un  ctrl;
    int                 res;

    memset(&ctrl, 0, sizeof(ctrl));
    ctrl.sun_family = AF_UNIX;
    strncpy(ctrl.sun_path, sock_name, sizeof(ctrl.sun_path) - 1);
    if((res = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
        perror("socket create");
        exit(1);
    }
    if(connect(res, (struct sockaddr *)&ctrl, (socklen_t)sizeof(ctrl)) < 0) {
        perror("connect");
        exit(1);
    }
    return res;
}

main(const int argc, char **argv)
{
    CTRL_CMD    cmd;
    int         sock, n_lstn, n_svc, n_be, n_sess;
    char        *arg0, *sock_name;
    int         c_opt, en_lst, de_lst, en_svc, de_svc, en_be, de_be, is_set;
    LISTENER    lstn;
    SERVICE     svc;
    BACKEND     be;
    SESS        sess;

    arg0 = *argv;
    sock_name = NULL;
    en_lst = de_lst = en_svc = de_svc = en_be = de_be = is_set = 0;
    memset(&cmd, 0, sizeof(cmd));
    opterr = 0;
    while((c_opt = getopt(argc, argv, "c:LlSsBb")) > 0)
        switch(c_opt) {
        case 'c':
            sock_name = optarg;
            break;
        case 'L':
            if(is_set)
                usage(arg0);
            en_lst = is_set = 1;
            break;
        case 'l':
            if(is_set)
                usage(arg0);
            de_lst = is_set = 1;
            break;
        case 'S':
            if(is_set)
                usage(arg0);
            en_svc = is_set = 1;
            break;
        case 's':
            if(is_set)
                usage(arg0);
            de_svc = is_set = 1;
            break;
        case 'B':
            if(is_set)
                usage(arg0);
            en_be = is_set = 1;
            break;
        case 'b':
            if(is_set)
                usage(arg0);
            de_be = is_set = 1;
            break;
        default:
            fprintf(stderr, "bad flag -%c", optopt);
            usage(arg0);
            break;
        }

    if(sock_name == NULL)
        usage(arg0);
    if(en_lst || de_lst) {
        if(optind != (argc - 1))
            usage(arg0);
        cmd.cmd = (en_lst? CTRL_EN_LSTN: CTRL_DE_LSTN);
        cmd.listener = atoi(argv[optind++]);
    }
    if(en_svc || de_svc) {
        if(optind != (argc - 2))
            usage(arg0);
        cmd.cmd = (en_svc? CTRL_EN_SVC: CTRL_DE_SVC);
        cmd.listener = atoi(argv[optind++]);
        cmd.service = atoi(argv[optind++]);
    }
    if(en_be || de_be) {
        if(optind != (argc - 3))
            usage(arg0);
        cmd.cmd = (en_be? CTRL_EN_BE: CTRL_DE_BE);
        cmd.listener = atoi(argv[optind++]);
        cmd.service = atoi(argv[optind++]);
        cmd.backend = atoi(argv[optind++]);
    }
    if(!is_set) {
        if(optind != argc)
            usage(arg0);
        cmd.cmd = CTRL_LST;
    }

    sock = get_sock(sock_name);
    write(sock, &cmd, sizeof(cmd));

    if (!is_set) {
        n_lstn = 0;
        while(read(sock, (void *)&lstn, sizeof(LISTENER)) == sizeof(LISTENER)) {
            if(lstn.disabled < 0)
                break;
            printf("%3d. %s Listener %s:%hd %s\n", n_lstn++, lstn.ctx? "HTTPS" : "http",
                inet_ntoa(lstn.addr.sin_addr), ntohs(lstn.addr.sin_port), lstn.disabled? "*D": "a");
            n_svc = 0;
            while(read(sock, (void *)&svc, sizeof(SERVICE)) == sizeof(SERVICE)) {
                if(svc.disabled < 0)
                    break;
                printf("  %3d. Service %s\n", n_svc++, svc.disabled? "*D": "a");
                n_be = 0;
                while(read(sock, (void *)&be, sizeof(BACKEND)) == sizeof(BACKEND)) {
                    if(be.disabled < 0)
                        break;
                    if(be.domain == PF_INET)
                        printf("    %3d. Backend PF_INET %s:%hd %s\n", n_be++, inet_ntoa(be.addr.in.sin_addr),
                            ntohs(be.addr.in.sin_port), be.disabled? "*D": "a");
                    else
                        printf("    %3d. Backend PF_UNIX %s %s\n", n_be++, be.addr.un.sun_path,
                            be.disabled? "*D": "");
                }
                n_sess = 0;
                while(read(sock, (void *)&sess, sizeof(SESS)) == sizeof(SESS)) {
                    if((int)sess.to_host < 0)
                        break;
                    printf("    %3d. Session %s -> %d\n", n_sess++, sess.key, (int)sess.to_host);
                }
            }
        }
        printf(" -1. Global services\n");
        n_svc = 0;
        while(read(sock, (void *)&svc, sizeof(SERVICE)) == sizeof(SERVICE)) {
            if(svc.disabled < 0)
                break;
            printf("  %3d. Service %s\n", n_svc++, svc.disabled? "*D": "a");
            n_be = 0;
            while(read(sock, (void *)&be, sizeof(BACKEND)) == sizeof(BACKEND)) {
                if(be.disabled < 0)
                    break;
                if(be.domain == PF_INET)
                    printf("    %3d. Backend PF_INET %s:%hd %s\n", n_be++, inet_ntoa(be.addr.in.sin_addr),
                        ntohs(be.addr.in.sin_port), be.disabled? "*D": "a");
                else
                    printf("    %3d. Backend PF_UNIX %s %s\n", n_be++, be.addr.un.sun_path,
                        be.disabled? "*D": "");
            }
            n_sess = 0;
            while(read(sock, (void *)&sess, sizeof(SESS)) == sizeof(SESS)) {
                if((int)sess.to_host < 0)
                    break;
                printf("    %3d. Session %s -> %d\n", n_sess++, sess.key, (int)sess.to_host);
            }
        }
    }
    return 0;
}
