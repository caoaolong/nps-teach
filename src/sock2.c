//
// Created by Administrator on 25-1-20.
//
#include <sock2.h>

// data
static int fd = 0;

Sock2Fd sock2fds[MAX_FDS];

void sock2_init() {
    for (int i = 0; i < MAX_FDS; i++) sock2fds[i].fd = -1;
}

Sock2Fd *sock2fd(int fd) {
    return &sock2fds[fd - 1];
}

int socket2(int domain, int type, int protocol) {
    if (fd >= MAX_FDS || fd < 0) return -1;
    Sock2Fd *sock2fd = &sock2fds[fd];
    fd++;
    sock2fd->domain = domain;
    sock2fd->type = type;
    sock2fd->protocol = protocol;
    sock2fd->fd = fd;
    sock2fd->state = CLOSED;
    return fd;
}

int bind2(int sockfd, struct sockaddr *addr, socklen_t addrlen) {
    if (sockfd >= MAX_FDS || sockfd < 0) return -1;
    Sock2Fd *sock2fd = &sock2fds[sockfd - 1];
    memcpy(&sock2fd->addr, addr, addrlen);
    // 注册服务
    int sid = -1;
    if (sock2fd->protocol == IPPROTO_TCP) {
        sid = service_register(SP_TCP, ((struct sockaddr_in*)addr)->sin_port, sockfd);
    } else if (sock2fd->protocol == IPPROTO_UDP) {
        sid = service_register(SP_UDP, ((struct sockaddr_in*)addr)->sin_port, sockfd);
    }
    if (sid >= 0) {
        sock2fd->sid = sid;
        return 0;
    }
    return sid;
}

int listen2(int sockfd, int backlog) {
    if (sockfd >= MAX_FDS || sockfd < 0) return -1;
    Sock2Fd *sock2fd = &sock2fds[sockfd - 1];
    sock2fd->backlog = backlog;
    sock2fd->state = LISTEN;
    return 0;
}

int accept2(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    if (sockfd >= MAX_FDS || sockfd < 0) return -1;
    Sock2Fd *sock2fd = &sock2fds[sockfd - 1];
    if (sock2fd->state != LISTEN) return -1;
    // TODO: 捕获SYN数据包, 传递解析函数 tcp_is(FLAG_SYN)
    // TODO: 发送[SYN,ACK]数据包
    sock2fd->state = SYN_RECEIVED;
    // TODO: 捕获SYN数据包, 传递解析函数 tcp_is(FLAG_ACK)
    sock2fd->state = ESTABLISHED;
    // TODO: 保存客户端信息
    return 0;
}

int connect2(int sockfd, struct sockaddr *addr, socklen_t addrlen) {
    // TODO: connect2
    return 0;
}

int send2(int sockfd, const void *buf, size_t len, int flags) {
    // TODO: send2
    return 0;
}

int recv2(int sockfd, void *buf, size_t len, int flags) {
    if (sockfd >= MAX_FDS || sockfd < 0) return -1;
    Sock2Fd *sock2fd = &sock2fds[sockfd - 1];
    // TODO: recv2
    // TODO: 捕获[FIN]数据包后, 发送[ACK]数据包
    sock2fd->state = CLOSE_WAIT;
    // TODO: 发送[FIN]数据包
    sock2fd->state = LAST_ACK;
    // TODO: 捕获[ACK]数据包后
    sock2fd->state = CLOSED;
    return 0;
}

int close2(int sockfd) {
    if (sockfd >= MAX_FDS || sockfd < 0) return -1;
    Sock2Fd *sock2fd = &sock2fds[sockfd - 1];
    // TODO: 发送FIN数据包
    sock2fd->state = FIN_WAIT1;
    // TODO: 捕获[ACK]数据包, 传递解析函数 tcp_is(FLAG_ACK)
    sock2fd->state = FIN_WAIT2;
    // TODO: 捕获[FIN]数据包, 传递解析函数 tcp_is(FLAG_FIN)
    sock2fd->state = TIME_WAIT;
    // TODO: 等待2MSL
    sock2fd->state = CLOSED;
    // 注销服务
    service_unregister(sock2fd->sid);
    return 0;
}
