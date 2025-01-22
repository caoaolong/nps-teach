#include <nps.h>
#include <sock2.h>


int main() {
    int sockfd = socket2(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket2");
        exit(1);
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8888);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
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

    close2(sockfd);
    return 0;
}
