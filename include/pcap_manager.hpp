#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>
#include <thread>
#include <atomic>

#ifdef COPSEC_HAS_PCAP
#include <pcap.h>
#endif

namespace copsec {

class PcapManager {
public:
    static PcapManager& get_instance();

    PcapManager() = default;
    ~PcapManager();

    PcapManager(const PcapManager&) = delete;
    PcapManager& operator=(const PcapManager&) = delete;

    bool initialize();
    void log_packet(const uint8_t* raw_packet, std::size_t length);
    void write_synthetic_http_packet(const std::string& src_ip,
                                     uint16_t src_port,
                                     const std::string& raw_payload);
    void shutdown();

    static bool ensure_capture_directories();
    static std::size_t purge_all_captures();

private:
    void capture_loop();

    std::mutex pcap_mutex_;
#ifdef COPSEC_HAS_PCAP
    pcap_t* capture_handle_ = nullptr;
    pcap_dumper_t* pcap_dumper_ = nullptr;
#endif
    std::atomic<bool> capture_running_{false};
    std::thread capture_thread_;
    bool initialized_ = false;
};

} // namespace copsec