#include <nps.h>
#include <sock2.h>

void init() {
    sock2_init();
}

int main() {
    init();
    // int sockfd = socket2(AF_INET, SOCK_STREAM, 0);
    // if (sockfd < 0) {
    //     perror("socket2");
    //     exit(1);
    // }
    // struct sockaddr_in addr;
    // addr.sin_family = AF_INET;
    // addr.sin_port = htons(8888);
    // addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    // int ret = bind2(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    // if (ret < 0) {
    //     perror("bind2");
    //     exit(1);
    // }
    // ret = listen2(sockfd, 5);
    // if (ret < 0) {
    //     perror("listen2");
    //     exit(1);
    // }
    //
    // close2(sockfd);

    pcap_if_t *alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];
    // 获取网卡
    pcap_if_t *device = device_find(alldevs, getenv("NCID"));
    if (device == nullptr) {
        fprintf(stderr, "No device found\n");
        return -1;
    }
    // 打开设备
    pcap_t *handle = pcap_open_live(device->name, 65536, 0, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Unable to open device: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return -1;
    }
    pcap_loop(handle, -1, device_handler, nullptr);

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}
