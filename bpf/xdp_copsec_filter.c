#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

// =============================================================================
//  1. LPM Trie Map for Fast CIDR Subnet and IP Dropping
// =============================================================================
struct lpm_key {
    __u32 prefixlen;
    __u32 ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, __u32); // 1 = drop
} block_lpm_map SEC(".maps");

// =============================================================================
//  2. Per-CPU Array for Lockless Metric Counters (100k+ PPS Zero-Contention)
// =============================================================================
enum metric_type_t {
    METRIC_TOTAL   = 0,
    METRIC_DROPPED = 1,
    METRIC_PASSED  = 2,
    METRIC_MAX     = 3
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, METRIC_MAX);
    __type(key, __u32);
    __type(value, __u64);
} metrics_map SEC(".maps");

static __always_inline void increment_metric(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&metrics_map, &key);
    if (val) {
        *val += 1;
    }
}

// =============================================================================
//  3. RingBuffer Map for Kernel-to-Userspace Drop Telemetry (512 KB Lockless)
// =============================================================================
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} telemetry_ringbuf SEC(".maps");

// Drop Reason Classifications
enum drop_reason_t {
    DROP_REASON_UNKNOWN    = 0,
    DROP_REASON_LPM_BLOCK  = 1,
    DROP_REASON_RATE_LIMIT = 2,
    DROP_REASON_SYN_FLOOD  = 3,
    DROP_REASON_MALFORMED  = 4
};

// 24-byte, 64-bit aligned drop event structure
// Layout: 4 (src_ip) + 4 (dst_ip) + 2 (src_port) + 2 (dst_port) + 1 (protocol) + 1 (drop_reason) + 2 (pad) + 8 (timestamp_ns) = 24 bytes
struct drop_event_t {
    __u32 src_ip;        // 4 bytes: IPv4 source address (network byte order)
    __u32 dst_ip;        // 4 bytes: IPv4 destination address (network byte order)
    __u16 src_port;      // 2 bytes: L4 source port (host byte order)
    __u16 dst_port;      // 2 bytes: L4 destination port (host byte order)
    __u8  protocol;      // 1 byte:  IP protocol (IPPROTO_TCP, IPPROTO_UDP, etc.)
    __u8  drop_reason;   // 1 byte:  Drop reason classification
    __u8  pad[2];        // 2 bytes: 64-bit boundary alignment padding
    __u64 timestamp_ns;  // 8 bytes: Monotonic nanosecond timestamp
} __attribute__((aligned(8)));

// Emit drop event to userspace ring buffer
static __always_inline void emit_drop_event(__u32 src_ip, __u32 dst_ip, __u16 src_port, __u16 dst_port, __u8 protocol, __u8 reason, __u64 now_ns) {
    struct drop_event_t *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct drop_event_t), 0);
    if (!event) {
        return;
    }

    event->src_ip = src_ip;
    event->dst_ip = dst_ip;
    event->src_port = src_port;
    event->dst_port = dst_port;
    event->protocol = protocol;
    event->drop_reason = reason;
    event->pad[0] = 0;
    event->pad[1] = 0;
    event->timestamp_ns = now_ns;

    bpf_ringbuf_submit(event, 0);
}

// =============================================================================
//  XDP Fast-Path Packet Filter
// =============================================================================
SEC("xdp")
int copsec_xdp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Track total incoming packets across CPU cores without lock contention
    increment_metric(METRIC_TOTAL);

    // 1. Strict Layer 2: Ethernet Header Boundary Verification
    struct ethhdr *eth = data;
    if (unlikely((void *)(eth + 1) > data_end)) {
        increment_metric(METRIC_PASSED);
        return XDP_PASS;
    }

    // Only process IPv4 packets; pass all non-IPv4 traffic (e.g. ARP, IPv6)
    if (unlikely(eth->h_proto != bpf_htons(ETH_P_IP))) {
        increment_metric(METRIC_PASSED);
        return XDP_PASS;
    }

    // 2. Strict Layer 3: IPv4 Header Boundary & Variable IHL Verification
    struct iphdr *ip = (void *)(eth + 1);
    if (unlikely((void *)(ip + 1) > data_end)) {
        increment_metric(METRIC_PASSED);
        return XDP_PASS;
    }

    __u32 ip_hl = ip->ihl * 4;
    if (unlikely(ip_hl < sizeof(struct iphdr) || (void *)ip + ip_hl > data_end)) {
        increment_metric(METRIC_PASSED);
        return XDP_PASS;
    }

    // 3. O(k) Longest Prefix Match (LPM) Trie CIDR Blocklist Lookup
    struct lpm_key key = {
        .prefixlen = 32,
        .ip = ip->saddr,
    };

    __u32 *blocked = bpf_map_lookup_elem(&block_lpm_map, &key);
    if (unlikely(blocked && *blocked == 1)) {
        __u16 src_port = 0;
        __u16 dst_port = 0;
        void *l4 = (void *)ip + ip_hl;

        // 4. Strict Layer 4 Header Boundary Verification (TCP / UDP)
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = l4;
            if (likely((void *)(tcp + 1) <= data_end)) {
                src_port = bpf_ntohs(tcp->source);
                dst_port = bpf_ntohs(tcp->dest);
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = l4;
            if (likely((void *)(udp + 1) <= data_end)) {
                src_port = bpf_ntohs(udp->source);
                dst_port = bpf_ntohs(udp->dest);
            }
        }

        // 5. Zero-Copy Telemetry Event Streaming via Lockless RingBuffer
        emit_drop_event(ip->saddr, ip->daddr, src_port, dst_port, ip->protocol, DROP_REASON_LPM_BLOCK, bpf_ktime_get_ns());

        increment_metric(METRIC_DROPPED);
        return XDP_DROP;
    }

    // Packet permitted: pass downstream
    increment_metric(METRIC_PASSED);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
