//
// Created by Administrator on 25-1-20.
//
#include <sock2.h>
#include <unistd.h>

// data
static int fd = 0;

Sock2Fd sock2fds[MAX_FDS];

static bool packet_is(Stack *stack, uint8_t protocol, uint8_t flags) {
    StackNode *top = stack_peek(stack);
    if (top == NULL || top->protocol != protocol) return false;
    return ((Tcp_Hdr*)top->data)->ff.flags & flags;
}

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
    nps_view();
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
    nps_view();
    return 0;
}

static Stack *receive_packet(Sock2Fd *sock2fd, uint8_t protocol, uint8_t flags) {
    Stack *stack;
    while (true) {
        usleep(100);
        stack = service_get_packet(sock2fd->sid, 1);
        if (!stack)
            continue;
        if (!packet_is(stack, protocol, flags)) {
            stack_pop(stack);
            continue;
        }
        break;
    }
    return stack;
}

int accept2(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    if (sockfd >= MAX_FDS || sockfd < 0) return -1;
    Sock2Fd *sock2fd = &sock2fds[sockfd - 1];
    if (sock2fd->state != LISTEN) return -1;
    // 捕获SYN数据包, 判断是否为 SYN
    Stack *stack = receive_packet(sock2fd, SP_TCP, FLAG_SYN);
    // 发送[SYN,ACK]数据包
    service_send_packet(sock2fd->sid, stack_build_tcp(stack, FLAG_SYN | FLAG_ACK, nullptr));
    sock2fd->state = SYN_RECEIVED;
    nps_view();
    // 捕获SYN数据包, 判断是否为 ACK
    stack = receive_packet(sock2fd, SP_TCP, FLAG_ACK);
    sock2fd->state = ESTABLISHED;
    nps_view();
    // 保存客户端信息
    *addr = stack_addr_info(stack);
    *addrlen = sizeof(*addr);
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
    Stack *stack = service_get_packet(sock2fd->sid, 1);
    if (packet_is(stack, SP_TCP, FLAG_FIN)) {
        // 捕获[FIN]数据包后, 发送[ACK]数据包
        stack = receive_packet(sock2fd, SP_TCP, FLAG_FIN);
        sock2fd->state = CLOSE_WAIT;
        nps_view();
        // 发送[FIN]数据包
        service_send_packet(sock2fd->sid, stack_build_tcp(stack, FLAG_ACK, nullptr));
        sock2fd->state = LAST_ACK;
        nps_view();
        // 捕获[ACK]数据包
        receive_packet(sock2fd, SP_TCP, FLAG_ACK);
        sock2fd->state = CLOSED;
        nps_view();
        // 注销服务
        service_unregister(sock2fd->sid);
    } else {
        // TODO: recv2
    }
    return 0;
}

int close2(int sockfd) {
    if (sockfd >= MAX_FDS || sockfd < 0) return -1;
    Sock2Fd *sock2fd = &sock2fds[sockfd - 1];
    Stack *stack = nullptr;
    // 发送FIN数据包
    service_send_packet(sock2fd->sid, stack_build_tcp(stack, FLAG_SYN | FLAG_ACK, nullptr));
    sock2fd->state = FIN_WAIT1;
    nps_view();
    stack = receive_packet(sock2fd, SP_TCP, FLAG_ACK);
    nps_view();
    // 捕获[FIN]数据包
    service_send_packet(sock2fd->sid, stack_build_tcp(stack, FLAG_FIN, nullptr));
    sock2fd->state = TIME_WAIT;
    nps_view();
    // 等待2MSL(MSL设置为60)
    usleep(2 * 60);
    sock2fd->state = CLOSED;
    nps_view();
    // 注销服务
    service_unregister(sock2fd->sid);
    return 0;
}
