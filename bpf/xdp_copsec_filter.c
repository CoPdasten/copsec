#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Dynamic quarantine entry metadata for line-rate kernel drops with TTL
struct ban_entry {
    __u64 ban_timestamp_ns;
    __u64 ttl_ns;
    __u32 reason_code;
};

// 1. Dynamic eBPF Ban Map modernized to BPF_MAP_TYPE_LRU_HASH with 131,072 entries
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, __u32);
    __type(value, struct ban_entry);
} banned_ips SEC(".maps");

// Backwards compatibility alias for legacy loader references
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
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

// 3. Asymmetric Tarpit IP Map (LRU Hash, 32,768 entries)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, __u32);
    __type(value, __u32); // 1 = active tarpit
} tarpit_ips SEC(".maps");

// 4. SYN-Proxy Configuration Map (Array: [0]=enabled (1/0), [1]=target_port)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} syn_proxy_config SEC(".maps");

// 5. Ring buffer map for zero-copy kernel-to-userspace drop telemetry (256 KB)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} telemetry_ringbuf SEC(".maps");

// Telemetry counters
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 6);
    __type(key, __u32);
    __type(value, __u64);
} xdp_counters SEC(".maps");

enum {
    COPSEC_PACKETS_PROCESSED   = 0,
    COPSEC_PACKETS_DROPPED     = 1,
    COPSEC_PACKETS_WHITELISTED = 2,
    COPSEC_SYN_COOKIES_ISSUED  = 3,
    COPSEC_SYN_COOKIES_PASSED  = 4,
    COPSEC_TARPIT_RESPONSES    = 5
};

// Drop reasons: 1: SYN Flood, 2: L7 DPI Signature, 3: Entropy Anomaly, 4: Rate Limit, 5: Tarpit, 6: SYN Cookie Fail
enum drop_reason_t {
    DROP_REASON_SYN_FLOOD       = 1,
    DROP_REASON_L7_DPI          = 2,
    DROP_REASON_ENTROPY_ANOMALY = 3,
    DROP_REASON_RATE_LIMIT      = 4,
    DROP_REASON_TARPIT          = 5,
    DROP_REASON_SYN_COOKIE_FAIL = 6
};

// Strict binary event structure aligned to 64-bit boundaries (Total: 24 bytes)
struct drop_event_t {
    __u32 src_ip;
    __u16 src_port;
    __u16 protocol;
    __u8  drop_reason;
    __u8  pad[7];
    __u64 timestamp_ns;
};

static __always_inline void increment_counter(__u32 key) {
    __u64* counter = bpf_map_lookup_elem(&xdp_counters, &key);
    if (counter) (*counter)++;
}

static __always_inline void emit_drop_event(struct iphdr *ip, void *data_end, __u8 reason, __u64 now_ns) {
    struct drop_event_t *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct drop_event_t), 0);
    if (!event) {
        return;
    }

    event->src_ip = ip->saddr;
    event->protocol = ip->protocol;
    event->drop_reason = reason;
    #pragma unroll
    for (int i = 0; i < 7; i++) {
        event->pad[i] = 0;
    }
    event->timestamp_ns = now_ns;

    __u16 src_port = 0;
    void *l4 = (void *)(ip + 1);
    if (ip->protocol == 6) { // IPPROTO_TCP
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) <= data_end) {
            src_port = bpf_ntohs(tcp->source);
        }
    } else if (ip->protocol == 17) { // IPPROTO_UDP
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) <= data_end) {
            src_port = bpf_ntohs(udp->source);
        }
    }
    event->src_port = src_port;

    bpf_ringbuf_submit(event, 0);
}

// -----------------------------------------------------------------------------
// Internet Checksum Helpers (RFC 793 / 1071 1's Complement Folded Accumulators)
// -----------------------------------------------------------------------------
static __always_inline __u16 csum_fold_helper(__u32 csum) {
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    __u16 folded = ~csum;
    return folded ? folded : 0xffff;
}

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

static __always_inline __u16 tcp_checksum_hdr(struct iphdr *iph, struct tcphdr *th) {
    th->check = 0;
    __u32 csum = 0;

    // IPv4 Pseudo-header
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

static __always_inline void swap_mac(struct ethhdr *eth) {
    __u8 tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp, ETH_ALEN);
}

// -----------------------------------------------------------------------------
// Asymmetric Zero-Window Tarpit Engine (XDP_TX)
// -----------------------------------------------------------------------------
static __always_inline int tarpit_process(struct ethhdr *eth, struct iphdr *ip, struct tcphdr *tcp, void *data_end) {
    if ((void *)(tcp + 1) > data_end) {
        return XDP_DROP;
    }

    // 1. Swap Layer 2 Ethernet Addresses
    swap_mac(eth);

    // 2. Swap Layer 3 IPv4 Endpoints
    __u32 tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;
    ip->ttl = 64;

    // 3. Swap Layer 4 TCP Ports
    __u16 tmp_port = tcp->source;
    tcp->source = tcp->dest;
    tcp->dest = tmp_port;

    __u32 old_seq = bpf_ntohl(tcp->seq);
    __u32 old_ack = bpf_ntohl(tcp->ack_seq);

    // 4. Update TCP Sequence / ACK numbers
    if (tcp->syn) {
        tcp->ack_seq = bpf_htonl(old_seq + 1);
        tcp->seq = bpf_htonl(1000);
    } else {
        tcp->ack_seq = bpf_htonl(old_seq + 1);
        tcp->seq = bpf_htonl(old_ack ? old_ack : 1000);
    }

    // 5. Force TCP Flags to pure ACK (Zero-Window Tarpit Response)
    tcp->syn = 0;
    tcp->rst = 0;
    tcp->fin = 0;
    tcp->psh = 0;
    tcp->urg = 0;
    tcp->ack = 1;

    // 6. Hardcode TCP Window Size to 0 to trap adversary scanners in deep wait state
    tcp->window = 0;

    // 7. Truncate payload to standard 20-byte TCP header
    tcp->doff = 5;
    ip->tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct tcphdr));

    // 8. Recalculate Checksums
    ip->check = ip_checksum(ip);
    tcp->check = tcp_checksum_hdr(ip, tcp);

    increment_counter(COPSEC_TARPIT_RESPONSES);
    return XDP_TX;
}

// -----------------------------------------------------------------------------
// In-Kernel Stateful SYN-Proxy Engine (bpf_tcp_raw_syncookie helpers)
// -----------------------------------------------------------------------------
static __always_inline int syn_proxy_process(struct ethhdr *eth, struct iphdr *ip, struct tcphdr *tcp, void *data_end) {
    if ((void *)(tcp + 1) > data_end) {
        return XDP_PASS;
    }

    // A. Intercept incoming TCP SYN packets (Handshake Phase 1)
    if (tcp->syn && !tcp->ack) {
        __u32 th_len = (tcp->doff >= 5 && tcp->doff <= 15) ? (tcp->doff * 4) : sizeof(struct tcphdr);
        if ((void *)tcp + th_len > data_end || th_len < sizeof(struct tcphdr)) {
            th_len = sizeof(struct tcphdr);
        }

        // Generate kernel cryptographic syncookie
        __s64 cookie = bpf_tcp_raw_gen_syncookie_ipv4(ip, tcp, th_len);
        if (cookie < 0) {
            // Helper unavailable or failed: fall back to kernel stack
            return XDP_PASS;
        }

        // Issue immediate synthetic SYN-ACK back to sender via XDP_TX
        swap_mac(eth);

        __u32 old_saddr = ip->saddr;
        ip->saddr = ip->daddr;
        ip->daddr = old_saddr;
        ip->ttl = 64;

        __u16 old_sport = tcp->source;
        tcp->source = tcp->dest;
        tcp->dest = old_sport;

        tcp->ack_seq = bpf_htonl(bpf_ntohl(tcp->seq) + 1);
        tcp->seq = bpf_htonl((__u32)cookie);

        tcp->syn = 1;
        tcp->ack = 1;
        tcp->rst = 0;
        tcp->fin = 0;
        tcp->psh = 0;
        tcp->urg = 0;
        tcp->window = bpf_htons(65535);

        tcp->doff = 5;
        ip->tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct tcphdr));

        ip->check = ip_checksum(ip);
        tcp->check = tcp_checksum_hdr(ip, tcp);

        increment_counter(COPSEC_SYN_COOKIES_ISSUED);
        return XDP_TX;
    }

    // B. Intercept incoming TCP ACK frames (Handshake Phase 3 Validation)
    if (!tcp->syn && tcp->ack && !tcp->rst && !tcp->fin) {
        long ret = bpf_tcp_raw_check_syncookie_ipv4(ip, tcp);
        if (ret == 0) {
            // Legitimate completed handshake! Pass to network stack
            increment_counter(COPSEC_SYN_COOKIES_PASSED);
            return XDP_PASS;
        } else if (ret == -13) { // -EACCES: invalid or forged syncookie
            emit_drop_event(ip, data_end, DROP_REASON_SYN_COOKIE_FAIL, bpf_ktime_get_ns());
            increment_counter(COPSEC_PACKETS_DROPPED);
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

SEC("xdp")
int copsec_xdp(struct xdp_md *ctx) {
    void* data_end = (void *)(long)ctx->data_end;
    void* data = (void *)(long)ctx->data;
    increment_counter(COPSEC_PACKETS_PROCESSED);

    struct ethhdr* eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;
    struct iphdr* ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    // 1. In-Kernel Whitelist Fast Bypass: Bypass all ban checks for trusted enterprise IPs
    __u32* is_whitelisted = bpf_map_lookup_elem(&whitelisted_ips, &ip->saddr);
    if (is_whitelisted && *is_whitelisted == 1) {
        increment_counter(COPSEC_PACKETS_WHITELISTED);
        return XDP_PASS;
    }

    // 2. Asymmetric Zero-Window Tarpit Inspection
    __u32* is_tarpitted = bpf_map_lookup_elem(&tarpit_ips, &ip->saddr);
    if (is_tarpitted && *is_tarpitted == 1 && ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        return tarpit_process(eth, ip, tcp, data_end);
    }

    // 3. Dynamic TTL Banned IPs Evaluation (LRU Hash Map: 131,072 entries)
    struct ban_entry* entry = bpf_map_lookup_elem(&banned_ips, &ip->saddr);
    if (entry) {
        __u64 now_ns = bpf_ktime_get_ns();
        // ttl_ns == 0 denotes permanent ban; otherwise check expiration
        if (entry->ttl_ns == 0 || now_ns < (entry->ban_timestamp_ns + entry->ttl_ns)) {
            // Check if entry is specifically marked for active defense tarpitting
            if (entry->reason_code == DROP_REASON_TARPIT && ip->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = (void *)(ip + 1);
                return tarpit_process(eth, ip, tcp, data_end);
            }

            __u8 reason = DROP_REASON_RATE_LIMIT;
            if (entry->reason_code >= 1 && entry->reason_code <= 6) {
                reason = (__u8)entry->reason_code;
            }
            emit_drop_event(ip, data_end, reason, now_ns);
            increment_counter(COPSEC_PACKETS_DROPPED);
            return XDP_DROP;
        }
    }

    // Fallback check against legacy ban_map
    __u64* legacy_expiry = bpf_map_lookup_elem(&ban_map, &ip->saddr);
    if (legacy_expiry && *legacy_expiry > bpf_ktime_get_ns() / 1000000000ULL) {
        emit_drop_event(ip, data_end, DROP_REASON_RATE_LIMIT, bpf_ktime_get_ns());
        increment_counter(COPSEC_PACKETS_DROPPED);
        return XDP_DROP;
    }

    // 4. In-Kernel Stateful SYN-Proxy Validation (TCP)
    if (ip->protocol == IPPROTO_TCP) {
        __u32 cfg_key = 0;
        __u32 *syn_proxy_on = bpf_map_lookup_elem(&syn_proxy_config, &cfg_key);
        // If config map has key 0 set to 1, or by default when configured
        if (syn_proxy_on && *syn_proxy_on == 1) {
            struct tcphdr *tcp = (void *)(ip + 1);
            int syn_res = syn_proxy_process(eth, ip, tcp, data_end);
            if (syn_res != XDP_PASS) {
                return syn_res;
            }
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
