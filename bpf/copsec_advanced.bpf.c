#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

// =============================================================================
//  1. Dynamic TTL Ban Map & Data Structures
// =============================================================================
struct ban_entry_t {
    __u64 expire_at_ns;
    __u32 reason;
} __attribute__((aligned(8)));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32); // IPv4 source address (network byte order)
    __type(value, struct ban_entry_t);
} dynamic_ttl_ban_map SEC(".maps");

// =============================================================================
//  2. Egress Rate-Limiting & C2 Choke Token Bucket Map
// =============================================================================
#define EGRESS_RATE_BYTES_PER_SEC (1024ULL * 1024ULL)     // 1 MB/s rate limit
#define EGRESS_BURST_CAPACITY     (2 * 1024ULL * 1024ULL) // 2 MB burst capacity

struct token_bucket_t {
    __u64 last_update_ns;
    __u64 tokens;
} __attribute__((aligned(8)));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32); // Destination IPv4 address
    __type(value, struct token_bucket_t);
} egress_rate_map SEC(".maps");

// =============================================================================
//  Helper Functions: Checksum & Cryptographic SYN Cookie Generation
// =============================================================================

// RFC 793 / 1071 16-bit 1's Complement Folded Accumulator
static __always_inline __u16 csum_fold_helper(__u32 csum) {
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return (__u16)(~csum);
}

// Compute IPv4 header checksum over 20-byte standard header
static __always_inline __u16 ip_checksum(struct iphdr *iph) {
    iph->check = 0;
    __u32 csum = 0;
    __u16 *p = (__u16 *)iph;
    #pragma unroll
    for (int i = 0; i < (int)(sizeof(struct iphdr) / 2); i++) {
        csum += *p++;
    }
    return csum_fold_helper(csum);
}

// Compute TCP checksum including IPv4 pseudo-header and TCP header
static __always_inline __u16 tcp_checksum_hdr(struct iphdr *iph, struct tcphdr *th) {
    th->check = 0;
    __u32 csum = 0;

    // IPv4 Pseudo-header (RFC 793)
    csum += (iph->saddr & 0xffff) + (iph->saddr >> 16);
    csum += (iph->daddr & 0xffff) + (iph->daddr >> 16);
    csum += bpf_htons(IPPROTO_TCP);
    csum += bpf_htons(sizeof(struct tcphdr));

    // TCP Header (20 bytes = 10 16-bit words)
    __u16 *p = (__u16 *)th;
    #pragma unroll
    for (int i = 0; i < (int)(sizeof(struct tcphdr) / 2); i++) {
        csum += *p++;
    }

    return csum_fold_helper(csum);
}

// In-place swap of Ethernet MAC addresses
static __always_inline void swap_mac(struct ethhdr *eth) {
    __u8 tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp, ETH_ALEN);
}

// In-Kernel Cryptographic SYN-Cookie Generator
static __always_inline __u32 compute_syn_cookie(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport, __u32 seq, __u64 now_ns) {
    // 32-bit time slot advancing every ~64 seconds
    __u32 time_slot = (__u32)(now_ns >> 36);
    // Avalanche mix of 4-tuple, client sequence number, and time slot
    __u32 h = 0x9e3779b9;
    h ^= saddr + 0x85ebca6b;
    h = (h << 13) | (h >> 19);
    h ^= daddr + 0xc2b2ae35;
    h = (h << 17) | (h >> 15);
    h ^= ((__u32)sport << 16) | dport;
    h ^= seq;
    h ^= time_slot;
    h ^= (h >> 16);
    h *= 0x85ebca6b;
    h ^= (h >> 13);
    h *= 0xc2b2ae35;
    h ^= (h >> 16);
    return h;
}

// =============================================================================
//  Hook 1: XDP Ingress (SYN-Cookie / SYN-Proxy & Autonomous Kernel TTL Ban)
// =============================================================================
SEC("xdp")
int copsec_ingress_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. Strict Layer 2 Ethernet Header Boundary Verification
    struct ethhdr *eth = data;
    if (unlikely((void *)(eth + 1) > data_end)) {
        return XDP_PASS;
    }

    if (unlikely(eth->h_proto != bpf_htons(ETH_P_IP))) {
        return XDP_PASS;
    }

    // 2. Strict Layer 3 IPv4 Header Boundary & IHL Verification
    struct iphdr *ip = (void *)(eth + 1);
    if (unlikely((void *)(ip + 1) > data_end)) {
        return XDP_PASS;
    }

    __u32 ip_hl = ip->ihl * 4;
    if (unlikely(ip_hl < sizeof(struct iphdr) || (void *)ip + ip_hl > data_end)) {
        return XDP_PASS;
    }

    // 3. Autonomous Kernel TTL Ban Verification & In-Kernel Eviction
    struct ban_entry_t *ban = bpf_map_lookup_elem(&dynamic_ttl_ban_map, &ip->saddr);
    if (unlikely(ban)) {
        __u64 now_ns = bpf_ktime_get_ns();
        if (now_ns < ban->expire_at_ns) {
            return XDP_DROP;
        }
        // Ban duration expired: autonomously evict entry directly in kernel space
        bpf_map_delete_elem(&dynamic_ttl_ban_map, &ip->saddr);
    }

    // 4. In-Kernel SYN-Cookie / SYN-Proxy Active Defense
    if (ip->protocol == IPPROTO_TCP) {
        void *l4 = (void *)ip + ip_hl;
        struct tcphdr *tcp = l4;
        if (unlikely((void *)(tcp + 1) > data_end)) {
            return XDP_PASS;
        }

        // Pure SYN packet: SYN=1, ACK=0, RST=0, FIN=0
        if (tcp->syn && !tcp->ack && !tcp->rst && !tcp->fin) {
            __u64 now_ns = bpf_ktime_get_ns();
            __u32 cookie = compute_syn_cookie(ip->saddr, ip->daddr, tcp->source, tcp->dest, bpf_ntohl(tcp->seq), now_ns);

            // In-place swap of Ethernet MAC addresses
            swap_mac(eth);

            // In-place swap of IPv4 source/destination addresses
            __u32 tmp_ip = ip->saddr;
            ip->saddr = ip->daddr;
            ip->daddr = tmp_ip;
            ip->ttl = 64;

            // In-place swap of TCP source/destination ports
            __u16 tmp_port = tcp->source;
            tcp->source = tcp->dest;
            tcp->dest = tmp_port;

            // Adjust TCP sequence and acknowledgment numbers
            tcp->ack_seq = bpf_htonl(bpf_ntohl(tcp->seq) + 1);
            tcp->seq = bpf_htonl(cookie);

            // Set TCP flags to synthetic SYN-ACK
            tcp->syn = 1;
            tcp->ack = 1;
            tcp->rst = 0;
            tcp->fin = 0;
            tcp->psh = 0;
            tcp->urg = 0;
            tcp->window = bpf_htons(65535);

            // Strip TCP options: standard 20-byte TCP header
            tcp->doff = 5;
            ip->tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct tcphdr));

            // Recalculate checksums using folded accumulators
            ip->check = ip_checksum(ip);
            tcp->check = tcp_checksum_hdr(ip, tcp);

            // Bounce back out the ingress interface without hitting host socket stack
            return XDP_TX;
        }
    }

    return XDP_PASS;
}

// =============================================================================
//  Hook 2: TC Egress (Token Bucket Bandwidth Cap & C2 Choke)
// =============================================================================
SEC("tc")
int copsec_egress_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 1. Layer 2 Ethernet Header Boundary Verification
    struct ethhdr *eth = data;
    if (unlikely((void *)(eth + 1) > data_end)) {
        return TC_ACT_OK;
    }

    if (unlikely(eth->h_proto != bpf_htons(ETH_P_IP))) {
        return TC_ACT_OK;
    }

    // 2. Layer 3 IPv4 Header Boundary Verification
    struct iphdr *ip = (void *)(eth + 1);
    if (unlikely((void *)(ip + 1) > data_end)) {
        return TC_ACT_OK;
    }

    __u32 daddr = ip->daddr;
    __u64 pkt_len = skb->len;
    __u64 now_ns = bpf_ktime_get_ns();

    // 3. Token Bucket Rate-Limiting per Destination IP
    struct token_bucket_t *tb = bpf_map_lookup_elem(&egress_rate_map, &daddr);
    if (!tb) {
        struct token_bucket_t new_tb = {
            .last_update_ns = now_ns,
            .tokens = EGRESS_BURST_CAPACITY,
        };
        if (pkt_len <= new_tb.tokens) {
            new_tb.tokens -= pkt_len;
        } else {
            return TC_ACT_SHOT;
        }
        bpf_map_update_elem(&egress_rate_map, &daddr, &new_tb, BPF_ANY);
        return TC_ACT_OK;
    }

    // Replenish tokens based on elapsed nanoseconds
    __u64 delta_ns = now_ns - tb->last_update_ns;
    if (delta_ns > 0) {
        __u64 tokens_to_add = (delta_ns * EGRESS_RATE_BYTES_PER_SEC) / 1000000000ULL;
        if (tokens_to_add > 0) {
            tb->tokens += tokens_to_add;
            if (tb->tokens > EGRESS_BURST_CAPACITY) {
                tb->tokens = EGRESS_BURST_CAPACITY;
            }
            tb->last_update_ns = now_ns;
        }
    }

    if (pkt_len <= tb->tokens) {
        tb->tokens -= pkt_len;
        return TC_ACT_OK;
    }

    // Packet exceeds token balance: drop to choke covert C2 exfiltration
    return TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
