#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

struct bpf_object;
struct bpf_link;

namespace copsec {

struct XdpStats {
    uint64_t packets_processed = 0;
    uint64_t packets_dropped = 0;
    uint64_t ips_blocked = 0;
    double drop_pps = 0.0;
};

class XdpBouncer {
public:
    static XdpBouncer& get_instance() {
        static XdpBouncer instance;
        return instance;
    }

    XdpBouncer(const XdpBouncer&) = delete;
    XdpBouncer& operator=(const XdpBouncer&) = delete;

    bool initialize(const std::vector<std::string>& interfaces);
    ~XdpBouncer();

    bool add_ip_to_blocklist(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        ip_blocklist_[ip] = true;
        stats_.ips_blocked++;
        return update_kernel_map(ip, true);
    }

    XdpStats refresh_kernel_stats();

    bool remove_ip_from_blocklist(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = ip_blocklist_.find(ip);
        if (it != ip_blocklist_.end()) {
            ip_blocklist_.erase(it);
            return update_kernel_map(ip, false);
        }
        return false;
    }

    void record_packet_drop(uint64_t count = 1) {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_.packets_dropped += count;
    }

    void record_packet_processed(uint64_t count = 1) {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_.packets_processed += count;
    }

    XdpStats get_stats() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return stats_;
    }

    std::string status_report() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::ostringstream out;
        out << "=== eBPF/XDP Packet Bouncer ===\n";
        out << "XDP Supported: " << (xdp_supported_ ? "yes" : "no (fallback to nftables)") << "\n";
        out << "Attached Interfaces: ";
        if (interfaces_.empty()) {
            out << "none\n";
        } else {
            for (size_t i = 0; i < interfaces_.size(); ++i) {
                if (i) out << ", ";
                out << interfaces_[i];
            }
            out << "\n";
        }
        out << "Packets Processed: " << stats_.packets_processed << "\n";
        out << "Packets Dropped: " << stats_.packets_dropped << "\n";
        out << "Drop PPS: " << stats_.drop_pps << "\n";
        out << "IPs Blocked: " << stats_.ips_blocked << "\n";
        return out.str();
    }

private:
    XdpBouncer() = default;

    bool update_kernel_map(const std::string& ip, bool add);
    void detach_all();

    mutable std::mutex mutex_;
    std::vector<std::string> interfaces_;
    bool xdp_supported_ = false;
    std::string xdp_mode_ = "nftables";
    std::unordered_map<std::string, bool> ip_blocklist_;
    int ban_map_fd_ = -1;
    int counters_map_fd_ = -1;
    std::vector<int> attached_ifindices_;
    std::vector<bpf_link*> links_;
    bpf_object* bpf_object_ = nullptr;
    mutable XdpStats stats_;
};

} // namespace copsec
