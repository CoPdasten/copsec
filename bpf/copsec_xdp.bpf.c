#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} ban_map SEC(".maps");

SEC("xdp")
int copsec_xdp(struct xdp_md *ctx) {
    void* data_end = (void *)(long)ctx->data_end;
    void* data = (void *)(long)ctx->data;
    struct ethhdr* eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr* ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    __u64* expiry = bpf_map_lookup_elem(&ban_map, &ip->saddr);
    if (expiry && *expiry > bpf_ktime_get_ns() / 1000000000ULL) return XDP_DROP;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";