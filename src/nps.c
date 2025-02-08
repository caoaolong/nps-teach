#include <nps.h>
#include <sock2.h>
#include <pthread.h>
#include <ncursesw/ncurses.h>

pthread_t envp;
pcap_t *handle;

void *nps_pcap_loop(void *handle) {
    int ret;
    struct pcap_pkthdr *hdr;
    u_char *data;
    while ((ret = pcap_next_ex(handle, &hdr, &data)) >= 0) {
        if (ret == 0) continue;
        device_handler(nullptr, hdr, data);
    }
    return handle;
}

pcap_if_t *alldevs = nullptr;

void env_init() {
    pcap_if_t *alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];
    // 获取网卡
    pcap_if_t *device = device_find(alldevs, getenv("NCID"));
    if (device == nullptr) {
        fprintf(stderr, "No device found\n");
        return;
    }
    // 打开设备
    handle = pcap_open_live(device->name, 65536, FALSE, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Unable to open device: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return;
    }
    service_init(handle);
    if (pthread_create(&envp, nullptr, nps_pcap_loop, handle) != 0) {
        perror("pthread_create");
        fprintf(stderr, "Unable to create environment thread\n");
    }
}

void nps_init() {
    sock2_init();
    env_init();
    view_init();
}

void nps_free() {
    pthread_cancel(envp);
    pcap_close(handle);
    pcap_freealldevs(alldevs);
}

int main() {
    // 初始化环境
    nps_init();
    // 显示界面
    nps_view();
    // 执行用户态协议
    nps_main();
    // 监听键盘事件
    while (true) {
        char c = getch();
        if (c == '\033') {
            endwin();
            break;
        }
        if (isprint(c)) {
            cmd_put_char(c);
        } else if (c == '\n') {
            cmd_exec();
        } else if (c == '\a') {
            cmd_pop_char();
        }
    }
    nps_free();
    return 0;
}
