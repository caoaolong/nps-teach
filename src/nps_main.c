﻿#include <nps.h>
#include <sock2.h>

extern struct in_addr HOST_IP;

void nps_main() {
    int sockfd = socket2(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("socket2");
        exit(1);
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8989);
    addr.sin_addr.s_addr = HOST_IP.s_addr;
    int ret = bind2(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    if (ret < 0) {
        perror("bind2");
        exit(1);
    }
    ret = listen2(sockfd, 5);
    if (ret < 0) {
        perror("listen2");
        exit(1);
    }
    struct sockaddr_in client;
    int size = sizeof(client);
    ret = accept2(sockfd, (struct sockaddr*)&client, &size);
    if (ret < 0) {
        perror("accept2");
        exit(1);
    }
    close2(sockfd);
}