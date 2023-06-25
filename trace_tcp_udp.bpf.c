#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct packet_info {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 app;
    __u32 pkt_size;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2);
    __uint(value_size, sizeof(struct packet_info));
    __uint(key_size, sizeof(__u8));
} packet_map SEC(".maps");

SEC("tracepoint/net/ipv4/tcp_sendmsg")
int trace_tcp(struct pt_regs *ctx)
{
    void *data = (void *)(uintptr_t)ctx->di;
    void *data_end = (void *)(uintptr_t)ctx->si;
    struct iphdr *iph = data + sizeof(struct ethhdr);
    struct tcphdr *tcphdr = (struct tcphdr *)(iph + 1);
    struct packet_info info = {};

    if ((void *)(tcphdr + 1) > data_end) {
        return 0;
    }

    info.src_ip = iph->saddr;
    info.dst_ip = iph->daddr;
    info.src_port = tcphdr->source;
    info.dst_port = tcphdr->dest;
    info.app = ntohs(tcphdr->source);
    info.pkt_size = ctx->ax;

    __u8 key = IPPROTO_TCP;
    bpf_map_update_elem(&packet_map, &key, &info, BPF_ANY);

    return 0;
}

SEC("tracepoint/net/ipv4/udp_sendmsg")
int trace_udp(struct pt_regs *ctx)
{
    void *data = (void *)(uintptr_t)ctx->di;
    void *data_end = (void *)(uintptr_t)ctx->si;
    struct iphdr *iph = data + sizeof(struct ethhdr);
    struct udphdr *udphdr = (struct udphdr *)(iph + 1);
    struct packet_info info = {};

    if ((void *)(udphdr + 1) > data_end) {
        return 0;
    }

    info.src_ip = iph->saddr;
    info.dst_ip = iph->daddr;
    info.src_port = udphdr->source;
    info.dst_port = udphdr->dest;
    info.app = ntohs(udphdr->source);
    info.pkt_size = ctx->ax;

    __u8 key = IPPROTO_UDP;
    bpf_map_update_elem(&packet_map, &key, &info, BPF_ANY);

    return 0;
}

char _license[] SEC("license") = "GPL";
