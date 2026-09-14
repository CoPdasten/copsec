#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
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

// Dynamic quarantine entry metadata for line-rate kernel drops with TTL
struct ban_entry {
    __u64 ban_timestamp_ns;
    __u64 ttl_ns;
    __u32 reason_code;
    __u32 pad;
};

// 128-bit IPv6 address key container
struct in6_addr_key {
    __u8 addr[16];
};

// 1. Dynamic eBPF Ban Map (IPv4) - BPF_MAP_TYPE_LRU_HASH with 131,072 entries
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, __u32);
    __type(value, struct ban_entry);
} banned_ips SEC(".maps");

// 1b. Dynamic eBPF Ban Map (IPv6) - BPF_MAP_TYPE_LRU_HASH with 65,536 entries
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct in6_addr_key);
    __type(value, struct ban_entry);
} banned_ips_v6 SEC(".maps");

// 2. In-Kernel Whitelist Map (IPv4) for line-rate fast bypass (XDP_PASS)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u32); // 1 = trusted / bypass
} whitelisted_ips SEC(".maps");

// 2b. In-Kernel Whitelist Map (IPv6) for line-rate fast bypass (XDP_PASS)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct in6_addr_key);
    __type(value, __u32); // 1 = trusted / bypass
} whitelisted_ips_v6 SEC(".maps");

// 3. Asymmetric Tarpit IP Map (IPv4) (LRU Hash, 32,768 entries)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, __u32);
    __type(value, __u32); // 1 = active tarpit
} tarpit_ips SEC(".maps");

// 3b. Asymmetric Tarpit IP Map (IPv6) (LRU Hash, 16,384 entries)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct in6_addr_key);
    __type(value, __u32); // 1 = active tarpit
} tarpit_ips_v6 SEC(".maps");

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

// 6. Auxiliary Ring buffer for live raw packet stream sampling (512 KB)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} raw_packet_ringbuf SEC(".maps");

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

// Dual-Stack binary event structure aligned to 64-bit boundaries (Total: 40 bytes)
struct drop_event_t {
    __u32 src_ip;        // IPv4 address in network order (or 0 if IPv6)
    __u16 src_port;      // L4 source port (host order)
    __u16 protocol;      // L4 protocol (e.g. 6=TCP, 17=UDP, 58=ICMPv6)
    __u8  drop_reason;   // Reason classification
    __u8  ip_version;    // 4 for IPv4, 6 for IPv6
    __u8  pad[6];        // 64-bit alignment padding
    __u64 timestamp_ns;  // Kernel monotonic timestamp in nanoseconds
    __u8  src_ip6[16];   // Full 128-bit address if ip_version == 6
};

// Live raw packet sample structure for forensics ring buffer (Total: 144 bytes)
struct packet_sample_t {
    __u32 pkt_len;       // Total packet wire length (ctx->data_end - ctx->data)
    __u16 capture_len;   // Truncated capture length (min(pkt_len, 128))
    __u8  drop_reason;   // Reason classification
    __u8  ip_version;    // 4 for IPv4, 6 for IPv6
    __u64 timestamp_ns;  // Monotonic timestamp
    __u8  data[128];     // Raw captured packet frame prefix
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
    event->ip_version = 4;
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        event->pad[i] = 0;
    }
    event->timestamp_ns = now_ns;
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        event->src_ip6[i] = 0;
    }

    __u16 src_port = 0;
    __u32 ip_hl = ip->ihl * 4;
    if (ip_hl >= sizeof(struct iphdr)) {
        void *l4 = (void *)ip + ip_hl;
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = l4;
            if ((void *)(tcp + 1) <= data_end) {
                src_port = bpf_ntohs(tcp->source);
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = l4;
            if ((void *)(udp + 1) <= data_end) {
                src_port = bpf_ntohs(udp->source);
            }
        }
    }
    event->src_port = src_port;

    bpf_ringbuf_submit(event, 0);
}

static __always_inline void emit_drop_event_v6(struct ipv6hdr *ip6, void *data_end, __u8 reason, __u64 now_ns) {
    struct drop_event_t *event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(struct drop_event_t), 0);
    if (!event) {
        return;
    }

    event->src_ip = 0;
    event->protocol = ip6->nexthdr;
    event->drop_reason = reason;
    event->ip_version = 6;
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        event->pad[i] = 0;
    }
    event->timestamp_ns = now_ns;
    __builtin_memcpy(event->src_ip6, &ip6->saddr, 16);

    __u16 src_port = 0;
    void *l4 = (void *)(ip6 + 1);
    if (ip6->nexthdr == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) <= data_end) {
            src_port = bpf_ntohs(tcp->source);
        }
    } else if (ip6->nexthdr == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) <= data_end) {
            src_port = bpf_ntohs(udp->source);
        }
    }
    event->src_port = src_port;

    bpf_ringbuf_submit(event, 0);
}

static __always_inline void emit_packet_sample(void *data, void *data_end, __u8 reason, __u8 ip_version, __u64 now_ns) {
    struct packet_sample_t *sample = bpf_ringbuf_reserve(&raw_packet_ringbuf, sizeof(struct packet_sample_t), 0);
    if (!sample) {
        return;
    }

    __u32 pkt_len = (__u32)(data_end - data);
    sample->pkt_len = pkt_len;
    __u16 cap_len = pkt_len > 128 ? 128 : (__u16)pkt_len;
    sample->capture_len = cap_len;
    sample->drop_reason = reason;
    sample->ip_version = ip_version;
    sample->timestamp_ns = now_ns;

    __builtin_memset(sample->data, 0, sizeof(sample->data));
    #pragma unroll
    for (int i = 0; i < 128; i++) {
        if (data + i + 1 <= data_end) {
            sample->data[i] = *((__u8 *)(data + i));
        } else {
            break;
        }
    }

    bpf_ringbuf_submit(sample, 0);
}

// -----------------------------------------------------------------------------
// Internet Checksum Helpers (RFC 793 / 1071 / 2460 1's Complement Folded Accumulators)
// -----------------------------------------------------------------------------
static __always_inline __u16 csum_fold_helper(__u32 csum) {
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return (__u16)(~csum);
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

static __always_inline __u16 tcp_checksum_ipv6(struct ipv6hdr *ip6, struct tcphdr *th) {
    th->check = 0;
    __u32 csum = 0;

    // IPv6 Pseudo-header: 16 bytes saddr + 16 bytes daddr
    __u16 *s = (__u16 *)&ip6->saddr;
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        csum += *s++;
    }

    __u16 *d = (__u16 *)&ip6->daddr;
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        csum += *d++;
    }

    // Upper-Layer Packet Length (32-bit field in RFC 2460)
    csum += bpf_htons(sizeof(struct tcphdr));

    // Next Header (32-bit field, 24-bit zero padding)
    csum += bpf_htons(IPPROTO_TCP);

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
// Asymmetric Zero-Window Tarpit Engine (IPv4 - XDP_TX)
// -----------------------------------------------------------------------------
static __always_inline int tarpit_process(struct ethhdr *eth, struct iphdr *ip, struct tcphdr *tcp, void *data_end) {
    if (unlikely((void *)(tcp + 1) > data_end)) {
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
    ip->ihl = 5;
    tcp->doff = 5;
    ip->tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct tcphdr));

    // 8. Recalculate Checksums
    ip->check = ip_checksum(ip);
    tcp->check = tcp_checksum_hdr(ip, tcp);

    increment_counter(COPSEC_TARPIT_RESPONSES);
    return XDP_TX;
}

// -----------------------------------------------------------------------------
// Asymmetric Zero-Window Tarpit Engine (IPv6 - XDP_TX)
// -----------------------------------------------------------------------------
static __always_inline int tarpit_process_v6(struct ethhdr *eth, struct ipv6hdr *ip6, struct tcphdr *tcp, void *data_end) {
    if (unlikely((void *)(tcp + 1) > data_end)) {
        return XDP_DROP;
    }

    // 1. Swap Layer 2 Ethernet Addresses
    swap_mac(eth);

    // 2. Swap Layer 3 IPv6 Endpoints (16 bytes each)
    struct in6_addr tmp_addr;
    __builtin_memcpy(&tmp_addr, &ip6->saddr, sizeof(struct in6_addr));
    __builtin_memcpy(&ip6->saddr, &ip6->daddr, sizeof(struct in6_addr));
    __builtin_memcpy(&ip6->daddr, &tmp_addr, sizeof(struct in6_addr));
    ip6->hop_limit = 64;

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

    // 6. Hardcode TCP Window Size to 0
    tcp->window = 0;

    // 7. Truncate payload to standard 20-byte TCP header
    tcp->doff = 5;
    ip6->payload_len = bpf_htons(sizeof(struct tcphdr));

    // 8. Recalculate IPv6 TCP Checksum
    tcp->check = tcp_checksum_ipv6(ip6, tcp);

    increment_counter(COPSEC_TARPIT_RESPONSES);
    return XDP_TX;
}

// -----------------------------------------------------------------------------
// In-Kernel Stateful SYN-Proxy Engine (IPv4)
// -----------------------------------------------------------------------------
static __always_inline int syn_proxy_process(struct ethhdr *eth, struct iphdr *ip, struct tcphdr *tcp, void *data_end) {
    if (unlikely((void *)(tcp + 1) > data_end)) {
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

        ip->ihl = 5;
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
            increment_counter(COPSEC_SYN_COOKIES_PASSED);
            return XDP_PASS;
        } else if (ret == -13) { // -EACCES: invalid or forged syncookie
            __u64 now_ns = bpf_ktime_get_ns();
            emit_drop_event(ip, data_end, DROP_REASON_SYN_COOKIE_FAIL, now_ns);
            emit_packet_sample((void *)eth, data_end, DROP_REASON_SYN_COOKIE_FAIL, 4, now_ns);
            increment_counter(COPSEC_PACKETS_DROPPED);
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

// -----------------------------------------------------------------------------
// In-Kernel Stateful SYN-Proxy Engine (IPv6)
// -----------------------------------------------------------------------------
static __always_inline int syn_proxy_process_v6(struct ethhdr *eth, struct ipv6hdr *ip6, struct tcphdr *tcp, void *data_end) {
    if (unlikely((void *)(tcp + 1) > data_end)) {
        return XDP_PASS;
    }

    // A. Intercept incoming TCP SYN packets (Handshake Phase 1)
    if (tcp->syn && !tcp->ack) {
        __u32 th_len = (tcp->doff >= 5 && tcp->doff <= 15) ? (tcp->doff * 4) : sizeof(struct tcphdr);
        if ((void *)tcp + th_len > data_end || th_len < sizeof(struct tcphdr)) {
            th_len = sizeof(struct tcphdr);
        }

        // Generate kernel cryptographic syncookie for IPv6
        __s64 cookie = bpf_tcp_raw_gen_syncookie_ipv6(ip6, tcp, th_len);
        if (cookie < 0) {
            return XDP_PASS;
        }

        swap_mac(eth);

        struct in6_addr old_saddr;
        __builtin_memcpy(&old_saddr, &ip6->saddr, sizeof(struct in6_addr));
        __builtin_memcpy(&ip6->saddr, &ip6->daddr, sizeof(struct in6_addr));
        __builtin_memcpy(&ip6->daddr, &old_saddr, sizeof(struct in6_addr));
        ip6->hop_limit = 64;

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
        ip6->payload_len = bpf_htons(sizeof(struct tcphdr));

        tcp->check = tcp_checksum_ipv6(ip6, tcp);

        increment_counter(COPSEC_SYN_COOKIES_ISSUED);
        return XDP_TX;
    }

    // B. Intercept incoming TCP ACK frames (Handshake Phase 3 Validation)
    if (!tcp->syn && tcp->ack && !tcp->rst && !tcp->fin) {
        long ret = bpf_tcp_raw_check_syncookie_ipv6(ip6, tcp);
        if (ret == 0) {
            increment_counter(COPSEC_SYN_COOKIES_PASSED);
            return XDP_PASS;
        } else if (ret == -13) {
            __u64 now_ns = bpf_ktime_get_ns();
            emit_drop_event_v6(ip6, data_end, DROP_REASON_SYN_COOKIE_FAIL, now_ns);
            emit_packet_sample((void *)eth, data_end, DROP_REASON_SYN_COOKIE_FAIL, 6, now_ns);
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
    if (unlikely((void *)(eth + 1) > data_end)) return XDP_PASS;

    __u16 proto = bpf_ntohs(eth->h_proto);

    // =========================================================================
    // BRANCH 1: IPv4 DATA-PLANE FAST-PATH
    // =========================================================================
    if (likely(proto == ETH_P_IP)) {
        struct iphdr* ip = (void *)(eth + 1);
        __u32 ip_hdr_len = ip->ihl * 4;
        if (unlikely(ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)) return XDP_PASS;

        // 0. Immutable Static Bypass for Private / Management / Loopback Networks (RFC 1918)
        __u32 saddr_host = bpf_ntohl(ip->saddr);
        if (unlikely((saddr_host & 0xFF000000) == 0x0A000000 ||   // 10.0.0.0/8
                     (saddr_host & 0xFFF00000) == 0xAC100000 ||   // 172.16.0.0/12
                     (saddr_host & 0xFFFF0000) == 0xC0A80000 ||   // 192.168.0.0/16
                     (saddr_host & 0xFF000000) == 0x7F000000)) {   // 127.0.0.0/8
            increment_counter(COPSEC_PACKETS_WHITELISTED);
            return XDP_PASS;
        }

        // 1. In-Kernel Whitelist Fast Bypass
        __u32* is_whitelisted = bpf_map_lookup_elem(&whitelisted_ips, &ip->saddr);
        if (unlikely(is_whitelisted && *is_whitelisted == 1)) {
            increment_counter(COPSEC_PACKETS_WHITELISTED);
            return XDP_PASS;
        }

        // 2. Dynamic TTL Banned IPs Evaluation (LRU Hash Map: 131,072 entries)
        struct ban_entry* entry = bpf_map_lookup_elem(&banned_ips, &ip->saddr);
        if (unlikely(entry)) {
            __u64 now_ns = bpf_ktime_get_ns();
            if (entry->ttl_ns == 0 || now_ns < (entry->ban_timestamp_ns + entry->ttl_ns)) {
                if (entry->reason_code == DROP_REASON_TARPIT && ip->protocol == IPPROTO_TCP) {
                    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
                    if ((void *)(tcp + 1) <= data_end) {
                        return tarpit_process(eth, ip, tcp, data_end);
                    }
                }

                __u8 reason = DROP_REASON_RATE_LIMIT;
                if (entry->reason_code >= 1 && entry->reason_code <= 6) {
                    reason = (__u8)entry->reason_code;
                }
                emit_drop_event(ip, data_end, reason, now_ns);
                emit_packet_sample(data, data_end, reason, 4, now_ns);
                increment_counter(COPSEC_PACKETS_DROPPED);
                return XDP_DROP;
            }
        }

        // 3. TCP-Specific Active Defenses: Asymmetric Zero-Window Tarpit & Stateful SYN-Proxy
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + ip_hdr_len;
            if (likely((void *)(tcp + 1) <= data_end)) {
                __u32* is_tarpitted = bpf_map_lookup_elem(&tarpit_ips, &ip->saddr);
                if (unlikely(is_tarpitted && *is_tarpitted == 1)) {
                    return tarpit_process(eth, ip, tcp, data_end);
                }

                __u32 cfg_key = 0;
                __u32 *syn_proxy_on = bpf_map_lookup_elem(&syn_proxy_config, &cfg_key);
                if (unlikely(syn_proxy_on && *syn_proxy_on == 1)) {
                    int syn_res = syn_proxy_process(eth, ip, tcp, data_end);
                    if (syn_res != XDP_PASS) {
                        return syn_res;
                    }
                }
            }
        }

        return XDP_PASS;
    }

    // =========================================================================
    // BRANCH 2: IPv6 DUAL-STACK DATA-PLANE FAST-PATH
    // =========================================================================
    else if (proto == ETH_P_IPV6) {
        struct ipv6hdr* ip6 = (void *)(eth + 1);
        if (unlikely((void *)(ip6 + 1) > data_end)) return XDP_PASS;

        // 1. Neighbor Discovery Protocol (NDP) Safeguard:
        // NEVER drop ICMPv6 Neighbor Solicitation/Advertisement or Router Solicitation/Advertisement
        // Types: 133=Router Solicit, 134=Router Advert, 135=Neighbor Solicit, 136=Neighbor Advert
        if (unlikely(ip6->nexthdr == IPPROTO_ICMPV6)) {
            struct icmp6hdr *icmp6 = (void *)(ip6 + 1);
            if ((void *)(icmp6 + 1) <= data_end) {
                if (icmp6->icmp6_type >= 133 && icmp6->icmp6_type <= 136) {
                    return XDP_PASS;
                }
            }
        }

        // 0. Immutable Static Bypass for IPv6 ULA (RFC 4193), Link-Local, and Loopback
        const __u8 *s6 = (const __u8 *)&ip6->saddr;
        if (unlikely((s6[0] & 0xFE) == 0xFC || // RFC 4193 ULA fc00::/7
                     (s6[0] == 0xFE && (s6[1] & 0xC0) == 0x80))) { // fe80::/10
            increment_counter(COPSEC_PACKETS_WHITELISTED);
            return XDP_PASS;
        }

        struct in6_addr_key v6_key;
        __builtin_memcpy(v6_key.addr, &ip6->saddr, 16);

        // 2. In-Kernel IPv6 Whitelist Fast Bypass
        __u32* is_whitelisted_v6 = bpf_map_lookup_elem(&whitelisted_ips_v6, &v6_key);
        if (unlikely(is_whitelisted_v6 && *is_whitelisted_v6 == 1)) {
            increment_counter(COPSEC_PACKETS_WHITELISTED);
            return XDP_PASS;
        }

        // 3. Dynamic TTL IPv6 Banned IPs Evaluation (LRU Hash Map: 65,536 entries)
        struct ban_entry* entry_v6 = bpf_map_lookup_elem(&banned_ips_v6, &v6_key);
        if (unlikely(entry_v6)) {
            __u64 now_ns = bpf_ktime_get_ns();
            if (entry_v6->ttl_ns == 0 || now_ns < (entry_v6->ban_timestamp_ns + entry_v6->ttl_ns)) {
                if (entry_v6->reason_code == DROP_REASON_TARPIT && ip6->nexthdr == IPPROTO_TCP) {
                    struct tcphdr *tcp = (void *)(ip6 + 1);
                    if ((void *)(tcp + 1) <= data_end) {
                        return tarpit_process_v6(eth, ip6, tcp, data_end);
                    }
                }

                __u8 reason = DROP_REASON_RATE_LIMIT;
                if (entry_v6->reason_code >= 1 && entry_v6->reason_code <= 6) {
                    reason = (__u8)entry_v6->reason_code;
                }
                emit_drop_event_v6(ip6, data_end, reason, now_ns);
                emit_packet_sample(data, data_end, reason, 6, now_ns);
                increment_counter(COPSEC_PACKETS_DROPPED);
                return XDP_DROP;
            }
        }

        // 4. IPv6 TCP-Specific Active Defenses: Asymmetric Zero-Window Tarpit & Stateful SYN-Proxy
        if (ip6->nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)(ip6 + 1);
            if (likely((void *)(tcp + 1) <= data_end)) {
                __u32* is_tarpitted_v6 = bpf_map_lookup_elem(&tarpit_ips_v6, &v6_key);
                if (unlikely(is_tarpitted_v6 && *is_tarpitted_v6 == 1)) {
                    return tarpit_process_v6(eth, ip6, tcp, data_end);
                }

                __u32 cfg_key = 0;
                __u32 *syn_proxy_on = bpf_map_lookup_elem(&syn_proxy_config, &cfg_key);
                if (unlikely(syn_proxy_on && *syn_proxy_on == 1)) {
                    int syn_res = syn_proxy_process_v6(eth, ip6, tcp, data_end);
                    if (syn_res != XDP_PASS) {
                        return syn_res;
                    }
                }
            }
        }

        return XDP_PASS;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
