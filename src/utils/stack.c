//
// Created by Administrator on 25-1-2.
//
#include <nps.h>
#include <prtc.h>
#include <stack.h>
#include <stdlib.h>

Stack *stack_new() {
    Stack *stack = malloc(sizeof(Stack));
    if (stack == NULL) return nullptr;
    stack->top = stack->bottom = nullptr;
    stack->size = 0;
    return stack;
}

void stack_push(Stack *stack, void *data, const uint8_t protocol, const uint16_t up_protocol) {
    StackNode *node = malloc(sizeof(StackNode));
    if (node == nullptr) return;
    node->data = data;
    node->protocol = protocol;
    node->up_protocol = up_protocol;
    node->up = node->down = nullptr;
    if (stack->bottom == nullptr) {
        stack->bottom = node;
    }
    if (stack->top != nullptr) {
        stack->top->up = node;
        node->down = stack->top;
    }
    stack->top = node;
    stack->size++;
}

StackNode *stack_pop(Stack *stack) {
    if (stack->top == NULL || stack->size == 0) return nullptr;
    StackNode *node = stack->top;
    if (stack->bottom == stack->top) {
        stack->bottom = nullptr;
    }
    stack->top = stack->top->down;
    if (stack->top == NULL || stack->size == 0) return nullptr;
    stack->top->up = nullptr;
    stack->size--;
    return node;
}

StackNode *stack_peek(const Stack *stack) {
    if (stack->top == nullptr) return nullptr;
    return stack->top;
}

_Bool stack_is_empty(const Stack *stack) {
    return stack->size == 0;
}

void stack_free(Stack *stack) {
    while (!stack_is_empty(stack)) {
        StackNode *node = stack_pop(stack);
        if (node != nullptr)
            free(node);
    }
    free(stack);
}

u_char *stack_encode(Stack *stack, int *size) {
    if (stack == nullptr || stack_is_empty(stack))
        return nullptr;
    // 编码协议栈
    uint8_t *data = malloc(1500);
    if (!data) return nullptr;
    memset(data, 0, 1500);
    uint8_t *pdata = data;
    // 用于记录链路层协议类型
    uint8_t lptype = 0;
    // 用于修改编码后数据的指针
    Ip_Hdr *epip = nullptr;


    StackNode *node = stack->bottom;
    while (node && node->protocol) {
        switch (node->protocol) {
            case SP_LB:
                lptype = SP_LB;
                *(uint32_t *) pdata = 2;
                pdata += 4;
                break;
            case SP_ETH:
                EthII_Hdr *eth_hdr = node->data;
                memcpy(pdata, eth_hdr, sizeof(EthII_Hdr));
                pdata += sizeof(EthII_Hdr);
                break;
            case SP_IPv4:
                Ip_Hdr *ip_hdr = node->data;
                // ip_hdr->len = htons(ip_hdr->len);
                // ip_hdr->identification = htons(ip_hdr->identification);
                // ip_hdr->ff.v = htons(ip_hdr->ff.v);
                // ip_hdr->src = htonl(ip_hdr->src);
                // ip_hdr->dst = htonl(ip_hdr->dst);
                memcpy(pdata, ip_hdr, sizeof(Ip_Hdr));
                epip = (Ip_Hdr *) pdata;
                pdata += sizeof(Ip_Hdr);
                break;
            case SP_TCP:
                Tcp_Hdr *tcp_hdr = node->data;
                // tcp_hdr->seq = htonl(tcp_hdr->seq);
                // tcp_hdr->ack = htonl(tcp_hdr->ack);
                // tcp_hdr->ff.v = htons(tcp_hdr->ff.v);
                // tcp_hdr->ws = htons(tcp_hdr->ws);
                memcpy(pdata, tcp_hdr, sizeof(Tcp_Hdr));
                pdata += sizeof(Tcp_Hdr);
                break;
            case SP_UDP:
                Udp_Hdr *udp_hdr = node->data;
                memcpy(pdata, udp_hdr, sizeof(Udp_Hdr));
                pdata += sizeof(Udp_Hdr);
                break;
            default:
                break;
        }
        node = node->up;
    }
    *size = (int) (pdata - data);
    if (lptype == SP_LB) {
        epip->len = htons(*size - 4);
    }
    return data;
}

Stack *stack_decode(const unsigned char *data, uint16_t *pport) {
    Stack *stack = stack_new();
    int top_type = SP_ETH;
    if (*(uint32_t *) data == 2) {
        top_type = SP_LB;
    }
    int port = 0;
    do {
        switch (top_type) {
            default:
                printf("Unknown packet type\n");
                stack_free(stack);
                return nullptr;
            case SP_LB:
                uint32_t *plb = malloc(4);
                *plb = *(uint32_t *) data;
                stack_push(stack, plb, SP_LB, top_type);
            // printf("Loopback\n");
                data += 4;
                top_type = SP_IPv4;
                break;
            case SP_ETH: {
                // 以太网帧头
                EthII_Hdr *eth_ii = eth_ii_parse(data);
                // 获取上层协议类型
                if (eth_ii->type == ETH_II_TYPE_ARP) {
                    top_type = SP_ARP;
                } else if (eth_ii->type == ETH_II_TYPE_IPv4) {
                    top_type = SP_IPv4;
                } else if (eth_ii->type == ETH_II_TYPE_IPv6) {
                    top_type = SP_IPv6;
                } else {
                    stack_free(stack);
                    return nullptr;
                }
                stack_push(stack, eth_ii, SP_ETH, top_type);
                // 计算长度偏移量
                data += sizeof(EthII_Hdr);
                // 输出
                // eth_ii_print(eth_ii);
                break;
            }
            case SP_ARP: {
                // ARP协议
                Arp_Hdr *arp_hdr = arp_parse(data);
                top_type = SP_NULL;
                stack_push(stack, arp_hdr, SP_ARP, top_type);
                // 计算长度偏移量
                data += sizeof(Arp_Hdr);
                // 输出
                // arp_print(arp_hdr);
                break;
            }
            case SP_IPv4: {
                Ip_Hdr *ip_hdr = ip_parse(data);
                if (!ip_hdr) {
                    stack_free(stack);
                    return nullptr;
                }
                // 获取上层协议类型
                if (ip_hdr->protocol == IPPROTO_ICMP) {
                    top_type = SP_ICMP;
                } else if (ip_hdr->protocol == IPPROTO_TCP) {
                    top_type = SP_TCP;
                } else if (ip_hdr->protocol == IPPROTO_UDP) {
                    top_type = SP_UDP;
                } else {
                    stack_free(stack);
                    return nullptr;
                }
                stack_push(stack, ip_hdr, SP_IPv4, top_type);
                // 计算长度偏移量
                data += ip_hdr->ihl * 4;
                // 输出
                // ip_print(ip_hdr);
                break;
            }
            case SP_ICMP: {
                const StackNode *node = stack_peek(stack);
                const uint16_t len = ((Ip_Hdr *) node->data)->len - ((Ip_Hdr *) node->data)->ihl * 4;
                Icmp_Hdr *icmp_hdr = icmp_parse(data, len);
                top_type = SP_NULL;
                stack_push(stack, icmp_hdr, SP_ICMP, top_type);
                // 计算长度偏移量
                data += len;
                // 输出
                // icmp_print(icmp_hdr);
                break;
            }
            case SP_UDP: {
                const StackNode *node = stack_peek(stack);
                const uint16_t len = ((Ip_Hdr *) node->data)->len - ((Ip_Hdr *) node->data)->ihl * 4;
                Udp_Hdr *udp_hdr = udp_parse(data, len);
                top_type = SP_NULL;
                port = udp_hdr->tp;
                stack_push(stack, udp_hdr, SP_UDP, top_type);
                // 计算长度偏移量
                data += len;
                // udp_print(udp_hdr);
                break;
            }
            case SP_TCP: {
                Tcp_Hdr *tcp_hdr = tcp_parse(data);
                top_type = SP_NULL;
                port = tcp_hdr->tp;
                stack_push(stack, tcp_hdr, SP_TCP, top_type);
                // 计算长度偏移量
                data += sizeof(Tcp_Hdr);
                // tcp_print(tcp_hdr);
                break;
            }
        }
    } while (top_type > 0);
    // fflush(stdout);
    *pport = port;
    return stack;
}

Stack *stack_build_tcp(Stack *src, uint8_t flags, u_char *data) {
    // 构建TCP包
    Stack *dst = stack_new();
    uint8_t top_type = SP_NULL;
    if (src) {
        StackNode *node = src->bottom;
        while (node && node->protocol) {
            switch (node->protocol) {
                case SP_LB:
                    uint32_t *plb = malloc(4);
                    memcpy(plb, node->data, sizeof(uint32_t));
                    top_type = SP_IPv4;
                    stack_push(dst, plb, SP_LB, top_type);
                    break;
                case SP_ETH:
                    EthII_Hdr *dst_eth_ii = malloc(sizeof(EthII_Hdr));
                    EthII_Hdr *src_eth_hdr = node->data;
                    memcpy(dst_eth_ii->source_mac, src_eth_hdr->target_mac, ETH_II_MAC_LEN);
                    memcpy(dst_eth_ii->target_mac, src_eth_hdr->source_mac, ETH_II_MAC_LEN);
                // 获取上层协议类型
                    if (src_eth_hdr->type == ETH_II_TYPE_ARP) {
                        top_type = SP_ARP;
                    } else if (src_eth_hdr->type == ETH_II_TYPE_IPv4) {
                        top_type = SP_IPv4;
                    } else if (src_eth_hdr->type == ETH_II_TYPE_IPv6) {
                        top_type = SP_IPv6;
                    } else {
                        stack_free(dst);
                        return nullptr;
                    }
                    stack_push(dst, dst_eth_ii, SP_ETH, top_type);
                    break;
                case SP_IPv4:
                    Ip_Hdr *dst_ip_hdr = malloc(sizeof(Ip_Hdr));
                    Ip_Hdr *src_ip_hdr = node->data;
                    memcpy(dst_ip_hdr, node->data, sizeof(Ip_Hdr));
                    dst_ip_hdr->src = src_ip_hdr->dst;
                    dst_ip_hdr->dst = src_ip_hdr->src;
                    dst_ip_hdr->ttl = 128;
                    dst_ip_hdr->identification = src_ip_hdr->identification + 1;
                // 获取上层协议类型
                    if (dst_ip_hdr->protocol == IPPROTO_ICMP) {
                        top_type = SP_ICMP;
                    } else if (dst_ip_hdr->protocol == IPPROTO_TCP) {
                        top_type = SP_TCP;
                    } else if (dst_ip_hdr->protocol == IPPROTO_UDP) {
                        top_type = SP_UDP;
                    } else {
                        stack_free(dst);
                        return nullptr;
                    }
                    stack_push(dst, dst_ip_hdr, SP_IPv4, top_type);
                    break;
                case SP_TCP:
                    Tcp_Hdr *dst_tcp_hdr = malloc(sizeof(Tcp_Hdr));
                    Tcp_Hdr *src_tcp_hdr = node->data;
                    memcpy(dst_tcp_hdr, node->data, sizeof(Tcp_Hdr));
                    dst_tcp_hdr->sp = src_tcp_hdr->tp;
                    dst_tcp_hdr->tp = src_tcp_hdr->sp;
                    dst_tcp_hdr->ff.flags = flags;
                    if (flags & FLAG_SYN) {
                        dst_tcp_hdr->seq++;
                    } else if (flags & FLAG_ACK) {
                        dst_tcp_hdr->ack++;
                    }
                    top_type = SP_NULL;
                    stack_push(dst, dst_tcp_hdr, SP_TCP, top_type);
                    break;
                default:
                    break;
            }
            node = node->up;
        }
    }
    return dst;
}

struct sockaddr stack_addr_info(Stack *stack) {
    // 获取地址信息
    struct sockaddr_in *addr = malloc(sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    StackNode *node = stack->bottom;
    while (node && node->up_protocol) {
        switch (node->protocol) {
            case SP_IPv4:
                Ip_Hdr *ip_hdr = node->data;
                addr->sin_addr.s_addr = ntohl(ip_hdr->src);
                break;
            case SP_TCP:
                Tcp_Hdr *tcp_hdr = node->data;
                addr->sin_port = htons(tcp_hdr->sp);
                break;
            default:
                break;
        }
        node = node->up;
    }
    return *(struct sockaddr *) addr;
}
