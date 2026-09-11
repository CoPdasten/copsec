#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

// Dynamic quarantine entry metadata for line-rate kernel drops with TTL
struct ban_entry {
    __u64 ban_timestamp_ns;
    __u64 ttl_ns;
    __u32 reason_code;
};

// 1. Dynamic eBPF Ban Map with TTL metadata
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct ban_entry);
} banned_ips SEC(".maps");

// Backwards compatibility alias for legacy loader references
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} ban_map SEC(".maps");

// 2. In-Kernel Whitelist Map for line-rate fast bypass (XDP_PASS)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u32); // 1 = trusted / bypass
} whitelisted_ips SEC(".maps");

// Telemetry counters
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} xdp_counters SEC(".maps");

enum {
    COPSEC_PACKETS_PROCESSED   = 0,
    COPSEC_PACKETS_DROPPED     = 1,
    COPSEC_PACKETS_WHITELISTED = 2
};

static __always_inline void increment_counter(__u32 key) {
    __u64* counter = bpf_map_lookup_elem(&xdp_counters, &key);
    if (counter) (*counter)++;
}

SEC("xdp")
int copsec_xdp(struct xdp_md *ctx) {
    void* data_end = (void *)(long)ctx->data_end;
    void* data = (void *)(long)ctx->data;
    increment_counter(COPSEC_PACKETS_PROCESSED);

    struct ethhdr* eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;
    struct iphdr* ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    // 1. In-Kernel Whitelist Fast Bypass: Bypass all ban checks for trusted enterprise IPs
    __u32* is_whitelisted = bpf_map_lookup_elem(&whitelisted_ips, &ip->saddr);
    if (is_whitelisted && *is_whitelisted == 1) {
        increment_counter(COPSEC_PACKETS_WHITELISTED);
        return XDP_PASS;
    }

    // 2. Dynamic TTL Banned IPs Evaluation
    struct ban_entry* entry = bpf_map_lookup_elem(&banned_ips, &ip->saddr);
    if (entry) {
        __u64 now_ns = bpf_ktime_get_ns();
        // ttl_ns == 0 denotes permanent ban; otherwise check expiration
        if (entry->ttl_ns == 0 || now_ns < (entry->ban_timestamp_ns + entry->ttl_ns)) {
            increment_counter(COPSEC_PACKETS_DROPPED);
            return XDP_DROP;
        }
    }

    // Fallback check against legacy ban_map
    __u64* legacy_expiry = bpf_map_lookup_elem(&ban_map, &ip->saddr);
    if (legacy_expiry && *legacy_expiry > bpf_ktime_get_ns() / 1000000000ULL) {
        increment_counter(COPSEC_PACKETS_DROPPED);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
