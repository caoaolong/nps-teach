//
// Created by Administrator on 25-1-2.
//
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