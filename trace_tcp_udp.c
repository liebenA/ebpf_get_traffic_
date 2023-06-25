#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>


struct packet_info {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 app;
    __u32 pkt_size;
};

int main() {
    int map_fd = bpf_obj_get("/sys/fs/bpf/tc/globals/packet_map");
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    while (1) {
        struct packet_info info;
        __u8 key;

        // TCP packets
        key = IPPROTO_TCP;
        if (bpf_map_lookup_elem(map_fd, &key, &info) == 0) {
            printf("TCP %s:%u -> %s:%u (%u bytes)\n",
                inet_ntoa(*(struct in_addr *)&info.src_ip), ntohs(info.src_port),
                inet_ntoa(*(struct in_addr *)&info.dst_ip), ntohs(info.dst_port),
                info.pkt_size);
        }

        // UDP packets
        key = IPPROTO_UDP;
        if (bpf_map_lookup_elem(map_fd, &key, &info) == 0) {
            printf("UDP %s:%u -> %s:%u (%u bytes)\n",
                inet_ntoa(*(struct in_addr *)&info.src_ip), ntohs(info.src_port),
                inet_ntoa(*(struct in_addr *)&info.dst_ip), ntohs(info.dst_port),
                info.pkt_size);
        }

        sleep(1);
    }

    close(map_fd);
    return 0;
}
