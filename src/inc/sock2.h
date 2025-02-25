#ifndef SOCK2_H
#define SOCK2_H

#include <prtc.h>
#include <sys/socket.h>

#define MAX_FDS         1024

typedef enum {
    CLOSED,
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT1,
    FIN_WAIT2,
    TIME_WAIT,
    LAST_ACK,
    CLOSE_WAIT
} TcpState;

typedef struct {
    int domain;
    int type;
    int protocol;
    int fd;
    uint16_t sid;
    TcpState state;
    union {
        struct sockaddr s;
        struct sockaddr_in si;
    } addr;

    int backlog;
} Sock2Fd;

void sock2_init();
Sock2Fd *sock2fd(int fd);

int socket2(int domain, int type, int protocol);
int bind2(int sockfd, struct sockaddr *addr, socklen_t addrlen);
int listen2(int sockfd, int backlog);

int accept2(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int connect2(int sockfd, struct sockaddr *addr, socklen_t addrlen);
int send2(int sockfd, const void *buf, size_t len, int flags);
int recv2(int sockfd, void *buf, size_t len, int flags);

int close2(int sockfd);

#endif
