#include "xdp_bouncer.hpp"

#include "logger.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <net/if.h>
#include <ctime>
#include <chrono>

#ifdef COPSEC_HAS_LIBBPF
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#endif

namespace copsec {

namespace {
#ifdef COPSEC_HAS_LIBBPF
std::string find_xdp_object() {
    for (const auto& path : {"/etc/copsec/copsec_xdp.bpf.o", "config/copsec_xdp.bpf.o", "build/bpf/copsec_xdp.bpf.o"}) {
        if (std::filesystem::is_regular_file(path)) return path;
    }
    return {};
}
#endif

#ifdef COPSEC_HAS_LIBBPF
bool parse_ipv4(const std::string& text, uint32_t& address) {
    return inet_pton(AF_INET, text.c_str(), &address) == 1;
}
#endif
}

XdpBouncer::~XdpBouncer() {
    std::lock_guard<std::mutex> lock(mutex_);
    detach_all();
}

bool XdpBouncer::initialize(const std::vector<std::string>& interfaces) {
    std::lock_guard<std::mutex> lock(mutex_);
    interfaces_ = interfaces;
    xdp_supported_ = false;
    xdp_mode_ = "nftables";

#ifdef COPSEC_HAS_LIBBPF
    const std::string object_path = find_xdp_object();
    if (object_path.empty()) {
        Logger::get_instance().log(LogLevel::INFO, "XDP_INIT",
            "XDP object is unavailable; retaining nftables enforcement.");
        return true;
    }

    bpf_object_ = bpf_object__open_file(object_path.c_str(), nullptr);
    if (!bpf_object_ || bpf_object__load(bpf_object_) != 0) {
        Logger::get_instance().log(LogLevel::INFO, "XDP_INIT",
            "eBPF load failed; retaining nftables enforcement: " + std::string(strerror(errno)));
        if (bpf_object_) bpf_object__close(bpf_object_);
        bpf_object_ = nullptr;
        return true;
    }

    bpf_program* program = bpf_object__find_program_by_name(bpf_object_, "copsec_xdp");
    bpf_map* ban_map = bpf_object__find_map_by_name(bpf_object_, "ban_map");
    bpf_map* counters_map = bpf_object__find_map_by_name(bpf_object_, "xdp_counters");
    if (!program || !ban_map || !counters_map) {
        Logger::get_instance().log(LogLevel::INFO, "XDP_INIT",
            "eBPF object is missing copsec_xdp or ban_map; retaining nftables enforcement.");
        bpf_object__close(bpf_object_);
        bpf_object_ = nullptr;
        return true;
    }
    ban_map_fd_ = bpf_map__fd(ban_map);
    counters_map_fd_ = bpf_map__fd(counters_map);

    for (const auto& interface : interfaces_) {
        const unsigned int ifindex = if_nametoindex(interface.c_str());
        if (ifindex == 0) continue;

        int flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
        int result = bpf_xdp_attach(static_cast<int>(ifindex), bpf_program__fd(program), flags, nullptr);
        if (result != 0) {
            flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
            result = bpf_xdp_attach(static_cast<int>(ifindex), bpf_program__fd(program), flags, nullptr);
        }

        if (result == 0) {
            attached_ifindices_.push_back(static_cast<int>(ifindex));
            xdp_mode_ = (flags & XDP_FLAGS_SKB_MODE) ? "generic" : "driver";
        } else {
            Logger::get_instance().log(LogLevel::INFO, "XDP_INIT",
                "XDP attach failed for " + interface + "; nftables remains active.");
        }
    }

    xdp_supported_ = !attached_ifindices_.empty();
    if (!xdp_supported_) {
        bpf_object__close(bpf_object_);
        bpf_object_ = nullptr;
        ban_map_fd_ = -1;
        counters_map_fd_ = -1;
    } else {
        Logger::get_instance().log(LogLevel::INFO, "XDP_INIT", "XDP attached in " + xdp_mode_ + " mode.");
    }
#else
    Logger::get_instance().log(LogLevel::INFO, "XDP_INIT",
        "libbpf is unavailable; retaining nftables enforcement.");
#endif
    return true;
}

XdpStats XdpBouncer::refresh_kernel_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
#ifdef COPSEC_HAS_LIBBPF
    if (counters_map_fd_ >= 0) {
        uint32_t processed_key = 0;
        uint32_t dropped_key = 1;
        uint64_t processed = 0;
        uint64_t dropped = 0;
        if (bpf_map_lookup_elem(counters_map_fd_, &processed_key, &processed) == 0 &&
            bpf_map_lookup_elem(counters_map_fd_, &dropped_key, &dropped) == 0) {
            const auto now = std::chrono::steady_clock::now();
            static auto previous_time = now;
            static uint64_t previous_dropped = 0;
            const double seconds = std::chrono::duration<double>(now - previous_time).count();
            stats_.drop_pps = seconds > 0.0 ? (dropped - previous_dropped) / seconds : 0.0;
            stats_.packets_processed = processed;
            stats_.packets_dropped = dropped;
            previous_time = now;
            previous_dropped = dropped;
        }
    }
#endif
    return stats_;
}

bool XdpBouncer::update_kernel_map(const std::string& ip, bool add) {
#ifdef COPSEC_HAS_LIBBPF
    if (ban_map_fd_ < 0) return true;
    uint32_t address = 0;
    if (!parse_ipv4(ip, address)) return false;
    if (add) {
        const uint64_t expiry = static_cast<uint64_t>(time(nullptr)) + 3600;
        return bpf_map_update_elem(ban_map_fd_, &address, &expiry, BPF_ANY) == 0;
    }
    return bpf_map_delete_elem(ban_map_fd_, &address) == 0 || errno == ENOENT;
#else
    (void)ip;
    (void)add;
    return true;
#endif
}

void XdpBouncer::detach_all() {
#ifdef COPSEC_HAS_LIBBPF
    for (const int ifindex : attached_ifindices_) {
        bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, nullptr);
        bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, nullptr);
    }
    attached_ifindices_.clear();
    if (bpf_object_) bpf_object__close(bpf_object_);
    bpf_object_ = nullptr;
    ban_map_fd_ = -1;
    counters_map_fd_ = -1;
#endif
}

} // namespace copsec