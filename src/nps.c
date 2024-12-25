#include <nps.h>

#include "prtc.h"

#define USE_FILTER

int main() {
    pcap_if_t *alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];
    // 获取网卡
    pcap_if_t *device = device_find(alldevs, getenv("NCID"));
    if (device == nullptr) {
        fprintf(stderr, "No device found\n");
        exit(-1);
    }
    // 打开设备
    pcap_t *handle = pcap_open_live(device->name, 65536, 0, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Unable to open device: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        exit(-1);
    }
#ifdef USE_FILTER
    // 设置过滤器
    struct bpf_program fp;
    char filter_exp[] = "arp";
    bpf_u_int32 net = 0;
    // 编译过滤器
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        printf("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(-1);
    }
#endif

    // 开始抓包
    // pcap_loop(handle, 5, device_handler, nullptr);

    // 发送 ARP Request
    arp_send(handle, nullptr, ARP_GRATUITOUS);

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}
