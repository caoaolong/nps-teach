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
    // TODO: 编码协议栈
    return nullptr;
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
    // TODO: 构建TCP包
    return nullptr;
}

struct sockaddr stack_addr_info(Stack *stack) {
    // TODO: 获取地址信息
    struct sockaddr addr;
    addr.sa_family = AF_INET;
    return addr;
}