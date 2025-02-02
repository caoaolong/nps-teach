//
// Created by Administrator on 25-1-22.
//

#ifndef SOCK2_H
#define SOCK2_H

#include <prtc.h>

// limits
#define MAX_FDS         1024

// domain
#define AF_INET        1

// type
#define SOCK_STREAM    1
#define SOCK_DGRAM     2

// protocol
#define IPPROTO_TCP    6
#define IPPROTO_UDP    17

// states
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
        struct sockaddr;
        struct sockaddr_in;
    } addr;

    int backlog;
} Sock2Fd;

void sock2_init();
int max_fd();

int socket2(int domain, int type, int protocol);
int bind2(int sockfd, struct sockaddr *addr, socklen_t addrlen);
int listen2(int sockfd, int backlog);

int accept2(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int connect2(int sockfd, struct sockaddr *addr, socklen_t addrlen);
int send2(int sockfd, const void *buf, size_t len, int flags);
int recv2(int sockfd, void *buf, size_t len, int flags);

int close2(int sockfd);

#endif //SOCK2_H
