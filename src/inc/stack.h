//
// Created by Administrator on 25-1-2.
//

#ifndef STACK_H
#define STACK_H

#include <stdint.h>
#include <stdbool.h>>

#define SP_NULL     0
#define SP_ETH      1
#define SP_ARP      2
#define SP_IPv4     3
#define SP_IPv6     4
#define SP_ICMP     5
#define SP_TCP      6
#define SP_UDP      7

typedef struct stack_node_t {
    uint8_t protocol;
    uint16_t up_protocol;
    void *data;
    struct stack_node_t *down;
    struct stack_node_t *up;
} StackNode;

typedef struct stack_t {
    StackNode *bottom;
    StackNode *top;
    int size;
} Stack;

Stack *stack_new();
void stack_push(Stack *stack, void *data, uint8_t protocol, uint16_t up_protocol);
StackNode *stack_pop(Stack *stack);
StackNode *stack_peek(const Stack *stack);
_Bool stack_is_empty(const Stack *stack);

#endif //STACK_H
