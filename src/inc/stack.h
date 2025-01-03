//
// Created by Administrator on 25-1-2.
//

#ifndef STACK_H
#define STACK_H

#include <stdint.h>

typedef struct stack_node_t {
    uint8_t protocol;
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
void stack_push(Stack *stack, void *data, uint8_t protocol);
StackNode *stack_pop(Stack *stack);
StackNode *stack_peek(const Stack *stack);

#endif //STACK_H
