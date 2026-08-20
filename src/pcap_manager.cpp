#include "pcap_manager.hpp"

#include "logger.hpp"
#include "pcap_capture.hpp"

#include <nlohmann/json.hpp>
#include <chrono>
#include <filesystem>
#include <sys/time.h>
#include <arpa/inet.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

namespace copsec {

namespace {

uint16_t checksum16(const uint8_t* data, std::size_t length) {
    uint32_t sum = 0;
    while (length > 1) {
        sum += (static_cast<uint16_t>(data[0]) << 8) | data[1];
        data += 2;
        length -= 2;
    }
    if (length) sum += static_cast<uint16_t>(data[0]) << 8;
    while (sum >> 16) sum = (sum & 0xffffU) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

uint16_t transport_checksum(const std::array<uint8_t, 20>& ip_header,
                             const std::vector<uint8_t>& tcp_segment) {
    std::vector<uint8_t> pseudo;
    pseudo.reserve(12 + tcp_segment.size() + (tcp_segment.size() & 1U));
    pseudo.insert(pseudo.end(), ip_header.begin() + 12, ip_header.begin() + 20);
    pseudo.insert(pseudo.end(), {0, 6});
    const uint16_t segment_length = htons(static_cast<uint16_t>(tcp_segment.size()));
    pseudo.push_back(static_cast<uint8_t>(segment_length >> 8));
    pseudo.push_back(static_cast<uint8_t>(segment_length & 0xff));
    pseudo.insert(pseudo.end(), tcp_segment.begin(), tcp_segment.end());
    if (pseudo.size() & 1U) pseudo.push_back(0);
    return checksum16(pseudo.data(), pseudo.size());
}

} // namespace

PcapManager& PcapManager::get_instance() {
    static PcapManager manager;
    return manager;
}

PcapManager::~PcapManager() {
    shutdown();
}

bool PcapManager::initialize() {
    std::lock_guard<std::mutex> lock(pcap_mutex_);
    if (initialized_) return true;
    if (!ensure_capture_directories()) {
        Logger::get_instance().log(LogLevel::ERR, "PCAP_INIT",
            "Unable to create or set permissions on /var/log/copsec/pcaps.");
        return false;
    }

#ifdef COPSEC_HAS_PCAP
    const std::filesystem::path capture_path = "/var/log/copsec/pcaps/copsec_capture.pcap";
    char error_buffer[PCAP_ERRBUF_SIZE]{};
    capture_handle_ = pcap_open_live("any", 65535, 1, 10, error_buffer);
    if (!capture_handle_) {
        Logger::get_instance().log(LogLevel::ERR, "PCAP_INIT",
            std::string("pcap_open_live(any) failed: ") + error_buffer + ". Retrying loopback interface.");
        capture_handle_ = pcap_open_live("lo", 65535, 1, 10, error_buffer);
    }
    if (!capture_handle_) {
        Logger::get_instance().log(LogLevel::ERR, "PCAP_INIT",
            std::string("pcap_open_live(lo) failed: ") + error_buffer);
        return false;
    }

    pcap_dumper_ = pcap_dump_open(capture_handle_, capture_path.c_str());
    if (!pcap_dumper_) {
        Logger::get_instance().log(LogLevel::ERR, "PCAP_INIT",
            std::string("pcap_dump_open() failed for ") + capture_path.string() + ": " + pcap_geterr(capture_handle_));
        pcap_close(capture_handle_);
        capture_handle_ = nullptr;
        return false;
    }
    // pcap_dump_open writes the global header; flush it before capture starts.
    pcap_dump_flush(pcap_dumper_);
    initialized_ = true;
    capture_running_ = true;
    capture_thread_ = std::thread(&PcapManager::capture_loop, this);
    return true;
#else
    Logger::get_instance().log(LogLevel::WARN, "PCAP_INIT",
        "libpcap is unavailable; raw packet dumping is disabled.");
    return false;
#endif
}

void PcapManager::log_packet(const uint8_t* raw_packet, std::size_t length) {
    if (!raw_packet || length == 0) return;
    std::lock_guard<std::mutex> lock(pcap_mutex_);
#ifdef COPSEC_HAS_PCAP
    pcap_pkthdr header{};
    gettimeofday(&header.ts, nullptr);
    header.caplen = static_cast<bpf_u_int32>(length);
    header.len = static_cast<bpf_u_int32>(length);
    if (pcap_dumper_) {
        pcap_dump(reinterpret_cast<u_char*>(pcap_dumper_), &header, raw_packet);
        pcap_dump_flush(pcap_dumper_);
    }
#else
    (void)length;
#endif
}

void PcapManager::capture_loop() {
#ifdef COPSEC_HAS_PCAP
    while (capture_running_) {
        pcap_pkthdr* header = nullptr;
        const u_char* packet = nullptr;
        pcap_t* handle = nullptr;
        {
            std::lock_guard<std::mutex> lock(pcap_mutex_);
            handle = capture_handle_;
        }
        if (!handle) break;

        const int result = pcap_next_ex(handle, &header, &packet);
        if (result == 1 && header && packet) {
            std::lock_guard<std::mutex> lock(pcap_mutex_);
            if (pcap_dumper_) {
                pcap_dump(reinterpret_cast<u_char*>(pcap_dumper_), header, packet);
                pcap_dump_flush(pcap_dumper_);
            }
        } else if (result == -1 || result == -2) {
            Logger::get_instance().log(LogLevel::ERR, "PCAP_CAPTURE",
                result == -1 ? pcap_geterr(handle) : "Live capture loop terminated.");
            break;
        }
    }
#endif
}

void PcapManager::write_synthetic_http_packet(const std::string& src_ip,
                                              uint16_t src_port,
                                              const std::string& raw_payload) {
    if (raw_payload.empty()) return;

    in_addr source_address{};
    if (inet_pton(AF_INET, src_ip.c_str(), &source_address) != 1) {
        source_address.s_addr = htonl(INADDR_LOOPBACK);
    }

    constexpr std::size_t ethernet_length = 14;
    constexpr std::size_t ip_length = 20;
    constexpr std::size_t tcp_length = 20;
    const std::size_t payload_length = std::min<std::size_t>(raw_payload.size(), 65535 - ethernet_length - ip_length - tcp_length);
    std::vector<uint8_t> packet(ethernet_length + ip_length + tcp_length + payload_length, 0);

    // Ethernet II: deterministic locally-administered endpoints, IPv4 EtherType.
    const std::array<uint8_t, 6> destination_mac{0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    const std::array<uint8_t, 6> source_mac{0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    std::copy(destination_mac.begin(), destination_mac.end(), packet.begin());
    std::copy(source_mac.begin(), source_mac.end(), packet.begin() + 6);
    packet[12] = 0x08;
    packet[13] = 0x00;

    std::array<uint8_t, 20> ip_header{};
    ip_header[0] = 0x45;
    const uint16_t total_length = htons(static_cast<uint16_t>(ip_length + tcp_length + payload_length));
    std::memcpy(ip_header.data() + 2, &total_length, sizeof(total_length));
    ip_header[8] = 64;
    ip_header[9] = IPPROTO_TCP;
    std::memcpy(ip_header.data() + 12, &source_address.s_addr, sizeof(source_address.s_addr));
    const uint32_t destination_address = htonl(INADDR_LOOPBACK);
    std::memcpy(ip_header.data() + 16, &destination_address, sizeof(destination_address));
    const uint16_t ip_checksum = htons(checksum16(ip_header.data(), ip_header.size()));
    std::memcpy(ip_header.data() + 10, &ip_checksum, sizeof(ip_checksum));
    std::copy(ip_header.begin(), ip_header.end(), packet.begin() + ethernet_length);

    std::vector<uint8_t> tcp_segment(tcp_length + payload_length, 0);
    const uint16_t network_source_port = htons(src_port == 0 ? 49152 : src_port);
    const uint16_t network_destination_port = htons(payload_length >= 5 && raw_payload.find("HTTPS") != std::string::npos ? 443 : 80);
    std::memcpy(tcp_segment.data(), &network_source_port, sizeof(network_source_port));
    std::memcpy(tcp_segment.data() + 2, &network_destination_port, sizeof(network_destination_port));
    tcp_segment[4] = 0;
    tcp_segment[5] = 1;
    tcp_segment[8] = 0;
    tcp_segment[9] = 1;
    tcp_segment[12] = 0x50;
    tcp_segment[13] = 0x18; // PSH | ACK
    const uint16_t window = htons(65535);
    std::memcpy(tcp_segment.data() + 14, &window, sizeof(window));
    std::copy(raw_payload.begin(), raw_payload.begin() + static_cast<std::ptrdiff_t>(payload_length), tcp_segment.begin() + tcp_length);
    const uint16_t tcp_checksum = htons(transport_checksum(ip_header, tcp_segment));
    std::memcpy(tcp_segment.data() + 16, &tcp_checksum, sizeof(tcp_checksum));
    std::copy(tcp_segment.begin(), tcp_segment.end(), packet.begin() + ethernet_length + ip_length);

    log_packet(packet.data(), packet.size());
}

void PcapManager::shutdown() {
    capture_running_ = false;
#ifdef COPSEC_HAS_PCAP
    {
        std::lock_guard<std::mutex> lock(pcap_mutex_);
        if (capture_handle_) pcap_breakloop(capture_handle_);
    }
#endif
    if (capture_thread_.joinable()) capture_thread_.join();
    std::lock_guard<std::mutex> lock(pcap_mutex_);
#ifdef COPSEC_HAS_PCAP
    if (pcap_dumper_) {
        pcap_dump_flush(pcap_dumper_);
        pcap_dump_close(pcap_dumper_);
        pcap_dumper_ = nullptr;
    }
    if (capture_handle_) {
        pcap_close(capture_handle_);
        capture_handle_ = nullptr;
    }
#endif
    initialized_ = false;
}

bool PcapManager::ensure_capture_directories() {
    bool success = true;
    for (const auto& directory : {std::filesystem::path("/var/log/copsec/pcap"),
                                  std::filesystem::path("/var/log/copsec/pcaps")}) {
        std::error_code error;
        std::filesystem::create_directories(directory, error);
        if (error) {
            success = false;
            continue;
        }
        std::filesystem::permissions(directory,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
            std::filesystem::perms::owner_exec | std::filesystem::perms::group_read |
            std::filesystem::perms::group_exec | std::filesystem::perms::others_read |
            std::filesystem::perms::others_exec,
            std::filesystem::perm_options::replace, error);
        if (error) success = false;
    }
    return success;
}

std::size_t PcapManager::purge_all_captures() {
    auto& manager = get_instance();
    manager.shutdown();
    auto& forensics = PcapForensics::get_instance();
    forensics.stop();

    std::size_t deleted_count = 0;
    std::error_code ec;
    const std::filesystem::path standard_directory = "/var/log/copsec/pcaps";
    if (!std::filesystem::exists(standard_directory, ec) || ec) {
        Logger::get_instance().log(LogLevel::ERR, "PCAP_PURGE_FAILED",
            "Capture directory is unavailable: " + standard_directory.string());
        return std::numeric_limits<std::size_t>::max();
    }
    for (const auto& entry : std::filesystem::directory_iterator(standard_directory, ec)) {
        if (ec) {
            Logger::get_instance().log(LogLevel::ERR, "PCAP_PURGE_FAILED",
                "Unable to enumerate capture directory: " + ec.message());
            return std::numeric_limits<std::size_t>::max();
        }
        if (!entry.is_regular_file(ec)) continue;
        const auto extension = entry.path().extension().string();
        if (extension != ".pcap" && extension != ".pcapng") continue;
        std::error_code remove_error;
        if (std::filesystem::remove(entry.path(), remove_error) && !remove_error) {
            ++deleted_count;
        } else if (remove_error) {
            Logger::get_instance().log(LogLevel::ERR, "PCAP_PURGE_FAILED",
                "Unable to remove " + entry.path().string() + ": " + remove_error.message());
            return std::numeric_limits<std::size_t>::max();
        }
    }
    if (!manager.initialize()) {
        Logger::get_instance().log(LogLevel::ERR, "PCAP_PURGE_FAILED",
            "Captures were deleted, but the active capture could not be reinitialized.");
        return std::numeric_limits<std::size_t>::max();
    }
    forensics.start("any");
    if (!forensics.initialize()) {
        Logger::get_instance().log(LogLevel::ERR, "PCAP_PURGE_FAILED",
            "Captures were deleted, but forensic capture could not be reinitialized.");
        return std::numeric_limits<std::size_t>::max();
    }
    Logger::get_instance().log(LogLevel::INFO, "PCAP_PURGE_EXECUTED",
        nlohmann::json({{"event_type", "PCAP_PURGE_EXECUTED"},
                        {"deleted_count", deleted_count}}).dump(),
        "INFO", "purge", "", "", "", 0, 0, "", "", "", "", "", "", "", "system");
    return deleted_count;
}

} // namespace copsec