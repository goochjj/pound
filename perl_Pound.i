// File : test.i
%module Pound
%{
#include "pound.h"
%}

// Everything is readonly
%readonly

// Commands

int getCommandSize();
void sendListCommand(SV *);

%inline %{

int getCommandSize() { return sizeof(CTRL_CMD); }

void sendCommand(SV *sock, CTRL_CMD *cmd) {
  PerlIO *pio = IoOFP(sv_2io(sock));
  PerlIO_write(pio, cmd, sizeof(*cmd));
  PerlIO_flush(pio);
}

void sendListCommand(SV *sock) {
  CTRL_CMD cmd;

  memset(&cmd, 0x00, sizeof(cmd));
  cmd.cmd = CTRL_LST;
  sendCommand(sock, &cmd);
}

void enableListener(SV *sock, int listener) {
  CTRL_CMD cmd;

  memset(&cmd, 0x00, sizeof(cmd));
  cmd.cmd = CTRL_EN_LSTN;
  cmd.listener = listener;
  sendCommand(sock, &cmd);
}

void disableListener(SV *sock, int listener) {
  CTRL_CMD cmd;

  memset(&cmd, 0x00, sizeof(cmd));
  cmd.cmd = CTRL_DE_LSTN;
  cmd.listener = listener;
  sendCommand(sock, &cmd);
}

void enableService(SV *sock, int listener, int service) {
  CTRL_CMD cmd;

  memset(&cmd, 0x00, sizeof(cmd));
  cmd.cmd = CTRL_EN_SVC;
  cmd.listener = listener;
  cmd.service = service;
  sendCommand(sock, &cmd);
}

void disableService(SV *sock, int listener, int service) {
  CTRL_CMD cmd;

  memset(&cmd, 0x00, sizeof(cmd));
  cmd.cmd = CTRL_DE_SVC;
  cmd.listener = listener;
  cmd.service = service;
  sendCommand(sock, &cmd);
}

void enableBackend(SV *sock, int listener, int service, int backend) {
  CTRL_CMD cmd;

  memset(&cmd, 0x00, sizeof(cmd));
  cmd.cmd = CTRL_EN_BE;
  cmd.listener = listener;
  cmd.service = service;
  cmd.backend = backend;
  sendCommand(sock, &cmd);
}

void disableBackend(SV *sock, int listener, int service, int backend) {
  CTRL_CMD cmd;

  memset(&cmd, 0x00, sizeof(cmd));
  cmd.cmd = CTRL_DE_BE;
  cmd.listener = listener;
  cmd.service = service;
  cmd.backend = backend;
  sendCommand(sock, &cmd);
}

%}

// Listeners
typedef struct _listener {
    // addr
    // ctx
    int magic;
    int                 sock;       /* listening socket */
    int                 clnt_check; /* client verification mode */
    int                 noHTTPS11;  /* HTTP 1.1 mode for SSL */
    int                 to;         /* client time-out */
    long                max_req;    /* max. request size */
    int                 rewr_loc;   /* rewrite location response */
    int                 rewr_dest;  /* rewrite destination header */
    int                 disabled;   /* true if the listener is disabled */
}   LISTENER;

%extend LISTENER {
  LISTENER() {
    LISTENER *ret = (LISTENER *)malloc(sizeof(LISTENER));
    if (ret) memset(ret, 0x00, sizeof(*ret));
    return ret;
  }
  ~LISTENER() { free(self); }

  void clear() { memset(self, 0x00, sizeof(*self)); }
  int getSize() { return sizeof(*self); }
  int loadFromSock(SV *sock) { 
    PerlIO *pio = IoIFP(sv_2io(sock));
    return (PerlIO_read(pio, self, sizeof(*self))==sizeof(*self));
  }
  char *getAddress() { return inet_ntoa(self->addr.sin_addr); }
  char *getProtocol() { return self->ctx? "HTTPS" : "http"; }
  int getPort() { return  ntohs(self->addr.sin_port); }
  int isValid() { return self->magic == LISTENER_MAGIC; }
  int isLast() { return self->disabled < 0; }
};

// Services
typedef struct _service {
  int magic;
  char *name;
  int tot_pri;
  USER_TYPE user_type;
  SESS_TYPE sess_type;
  int sess_ttl;
  int disabled;
} SERVICE;

%extend SERVICE {
  SERVICE() {
    SERVICE *ret = (SERVICE *)malloc(sizeof(SERVICE));
    if (ret) memset(ret, 0x00, sizeof(*ret));
    return ret;
  }
  ~SERVICE() { free(self); }

  void clear() { memset(self, 0x00, sizeof(*self)); }
  int getSize() { return sizeof(*self); }
  int loadFromSock(SV *sock) { 
    PerlIO *pio = IoIFP(sv_2io(sock));
    return (PerlIO_read(pio, self, sizeof(*self))==sizeof(*self));
  }
  char *getUserType() {
    switch (self->user_type) {
      case 0: return "none";
      case 1: return "cfauth";
      case 2: return "basic";
      case 3: return "token";
      default: return "unknown";
    }
  }
  char *getSessionType() {
    switch (self->sess_type) {
      case 0: return "none";
      case 1: return "ip";
      case 2: return "cookie";
      case 3: return "parm";
      case 4: return "header";
      case 5: return "basic";
      default: return "unknown";
    }
  }
  int isValid() { return self->magic == SERVICE_MAGIC; }
  int isLast() { return self->disabled < 0; }
};

// Backends
/* back-end types */
typedef enum    { BACK_END, REDIRECTOR }    BE_TYPE;
typedef enum    { SESS_NONE, SESS_IP, SESS_COOKIE, SESS_PARM, SESS_HEADER, SESS_BASIC }   SESS_TYPE;
typedef enum    { USER_NONE, USER_CFAUTH, USER_BASIC, USER_FORM, USER_AUTHTOKEN } USER_TYPE;

/* back-end definition */
typedef struct _backend {
    int magic;
    BE_TYPE             be_type;
    int                 domain;     /* PF_UNIX or PF_INET, in the future also PF_INET6 */
    //union {
     //   struct sockaddr_in  in;     /* IPv4 address */
     //   struct sockaddr_un  un;     /* UNIX "address" */
    //}                   addr;
    int                 priority;   /* priority */
    int                 to;
    struct sockaddr_in  HA;         /* HA address & port */
    //char                *url;       /* for redirectors */
    int                 redir_req;  /* the redirect should include the request path */
    //pthread_mutex_t     mut;        /* mutex for this back-end */
    int                 n_requests; /* number of requests seen */
    double              t_requests; /* time to answer these requests */
    double              t_average;  /* average time to answer requests */
    int                 alive;      /* false if the back-end is dead */
    int                 disabled;   /* true if the back-end is disabled */
    //struct _backend     *next;
}   BACKEND;

%extend BACKEND {
  BACKEND() {
    BACKEND *ret = (BACKEND *)malloc(sizeof(BACKEND));
    if (ret) memset(ret, 0x00, sizeof(*ret));
    return ret;
  }
  ~BACKEND() { free(self); }

  void clear() { memset(self, 0x00, sizeof(*self)); }
  int getSize() { return sizeof(*self); }
  int loadFromSock(SV *sock) { 
    PerlIO *pio = IoIFP(sv_2io(sock));
    return (PerlIO_read(pio, self, sizeof(*self))==sizeof(*self));
  }
  char *getAddress() { 
    if (self->domain == PF_INET) 
      return inet_ntoa(self->addr.in.sin_addr);
    else if (self->domain == PF_UNIX)
      return self->addr.un.sun_path;
    return "(unknown)";
  }
  int getPort() { 
    if (self->domain == PF_INET) 
      return ntohs(self->addr.in.sin_port);  
    return -1;
  }
  int isValid() { return self->magic == BACKEND_MAGIC; }
  int isLast() { return self->disabled < 0; }
};

// Sessions
typedef struct _sess {
    int magic;
    char                *key;  /* session key */
    int to_host;
    //BACKEND             *to_host;           /* backend pointer */
    long                  first_acc;          /* time of first access */
    long                  last_acc;           /* time of last access */
    //struct in_addr      last_ip;            /* Last IP Address */
    char                *last_url;          /* Last requested URL */
    char                *last_user;         /* Last username seen */
    int                 n_requests;         /* number of requests seen */
    int                 children;           /* number of children */
}   SESS;

%extend SESS {
  SESS() {
    SESS *ret = (SESS *)malloc(sizeof(SESS));
    if (ret) memset(ret, 0x00, sizeof(*ret));
    return ret;
  }
  ~SESS() { free(self); }

  void clear() { memset(self, 0x00, sizeof(*self)); }
  int getSize() { return sizeof(*self); }
  int loadFromSock(SV *sock) { 
    PerlIO *pio = IoIFP(sv_2io(sock));
    return (PerlIO_read(pio, self, sizeof(*self))==sizeof(*self));
  }
  char *getAddress() { return inet_ntoa(self->last_ip); }
  int getIdleTime() { return time(NULL) - self->last_acc; }
  int isValid() { return self->magic == SESS_MAGIC; }
  int isLast() { return ((int)self->to_host) < 0; }
};
