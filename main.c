#include <stdio.h>
#include <stdlib.h>
#define HAVE_REMOTE
#include "pcap.h"

int main(int argc, char *argv[]) {

    pcap_if_t *all_devices;
    int i=0;
    char eb[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &all_devices, eb) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", eb);
        exit(1);
    }

    for(const pcap_if_t *device = all_devices; device != NULL; device = device->next)
    {
        printf("%d. %s", ++i, device->name);
        if (device->description)
            printf(" (%s)\n", device->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return 1;
    }

    pcap_freealldevs(all_devices);

    return 0;
}