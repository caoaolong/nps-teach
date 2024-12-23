#include <nps.h>

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
    // 开始抓包
    pcap_loop(handle, 5, device_handler, nullptr);

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}
