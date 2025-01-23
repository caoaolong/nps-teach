//
// Created by admin on 25-1-15.
//
#include <prtc.h>
#include <sock2.h>

Tcp_Hdr *tcp_parse(const unsigned char *data) {
    Tcp_Hdr *tcp_hdr = malloc(sizeof(Tcp_Hdr));
    if (!tcp_hdr) return nullptr;
    memcpy(tcp_hdr, data, sizeof(Tcp_Hdr));
    // if (tcp_checksum(tcp_hdr) != 0) return nullptr;

    tcp_hdr->sp = ntohs(tcp_hdr->sp);
    tcp_hdr->tp = ntohs(tcp_hdr->tp);
    tcp_hdr->seq = ntohl(tcp_hdr->seq);
    tcp_hdr->ack = ntohl(tcp_hdr->ack);
    tcp_hdr->ff.v = ntohs(tcp_hdr->ff.v);
    tcp_hdr->ws = ntohs(tcp_hdr->ws);
    tcp_hdr->up = ntohs(tcp_hdr->up);
    return tcp_hdr;
}

BOOL tcp_checksum(Tcp_Hdr *tcp_hdr) {
    return checksum(tcp_hdr, sizeof(Tcp_Hdr));
}

void tcp_print(const Tcp_Hdr *tcp) {
    printf("\t\t\t Port: %u -> %u\n", tcp->sp, tcp->tp);
}

extern Sock2Fd sock2fds[MAX_FDS];

void tcp_process(Stack *stack) {
    for (int i = 0; i < MAX_FDS; i++) {
        if (sock2fds[i].fd == -1)
            continue;
        // TODO: 处理协议栈
    }
}