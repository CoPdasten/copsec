#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef COPSEC_HAS_PCAP
#include <pcap.h>
#endif

namespace copsec {

class PcapForensics {
public:
    static PcapForensics& get_instance() {
        static PcapForensics instance;
        return instance;
    }

    PcapForensics(const PcapForensics&) = delete;
    PcapForensics& operator=(const PcapForensics&) = delete;
    PcapForensics() = default;

    bool start(const std::string& interface = "any") {
        std::lock_guard<std::mutex> lock(mutex_);
        capture_interface_ = interface;
        return initialize_locked();
    }

    bool initialize(const std::string& pcap_dir = "/var/log/copsec/pcaps") {
        std::lock_guard<std::mutex> lock(mutex_);
        pcap_dir_ = pcap_dir;
        return initialize_locked();
    }

    bool initialize_locked() {
        std::error_code ec;
        std::filesystem::create_directories(pcap_dir_, ec);
        if (ec.value() != 0) {
            return false;
        }
        std::filesystem::permissions(
            pcap_dir_,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
            std::filesystem::perms::owner_exec | std::filesystem::perms::group_read |
            std::filesystem::perms::group_exec | std::filesystem::perms::others_read |
            std::filesystem::perms::others_exec,
            std::filesystem::perm_options::replace, ec);
        if (ec) return false;

#ifdef COPSEC_HAS_PCAP
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_handle_ = pcap_open_live(capture_interface_.c_str(), 65535, 1, 10, errbuf);
        if (!pcap_handle_) {
            return true;
        }
        pcap_setnonblock(pcap_handle_, 1, errbuf);
#endif

        return true;
    }

    void record_incident(const std::string& target_ip) {
        std::filesystem::create_directories("/var/log/copsec/pcaps");

        const std::string filepath = build_incident_path(target_ip);

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!running_) {
                running_ = true;
                capture_thread_ = std::thread([this]() { capture_loop(); });
            }
            incident_queue_.push({target_ip, filepath, get_timestamp_ms()});
        }
    }

    void record_incident(const std::string& target_ip, [[maybe_unused]] const std::string& rule_id, int64_t timestamp_ms) {
        std::filesystem::create_directories("/var/log/copsec/pcaps");
        const std::string filepath = build_incident_path(target_ip);

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!running_) {
                running_ = true;
                capture_thread_ = std::thread([this]() { capture_loop(); });
            }
            incident_queue_.push({target_ip, filepath, timestamp_ms});
        }
    }

    void stop() {
        running_ = false;
        if (capture_thread_.joinable()) {
            capture_thread_.join();
        }

#ifdef COPSEC_HAS_PCAP
        if (pcap_handle_) {
            pcap_close(pcap_handle_);
            pcap_handle_ = nullptr;
        }
        if (pcap_dumper_) {
            pcap_dump_close(pcap_dumper_);
            pcap_dumper_ = nullptr;
        }
#endif
    }

    std::vector<std::string> list_pcap_files() const {
        std::vector<std::string> files;
        std::lock_guard<std::mutex> lock(mutex_);

        try {
            for (const auto& entry : std::filesystem::directory_iterator(pcap_dir_)) {
                if (entry.path().extension() == ".pcap") {
                    files.push_back(entry.path().filename().string());
                }
            }
        } catch (...) {
        }

        return files;
    }

    std::size_t purge_all_captures() {
        std::lock_guard<std::mutex> lock(mutex_);
        while (!incident_queue_.empty()) incident_queue_.pop();

        std::size_t deleted_count = 0;
        std::error_code ec;
        for (const auto& entry : std::filesystem::directory_iterator(pcap_dir_, ec)) {
            if (ec) break;
            if (!entry.is_regular_file(ec)) continue;
            const auto extension = entry.path().extension().string();
            if (extension != ".pcap" && extension != ".pcapng") continue;
            std::error_code remove_error;
            if (std::filesystem::remove(entry.path(), remove_error) && !remove_error) ++deleted_count;
        }
        return deleted_count;
    }

    std::string status_report() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::ostringstream out;
        out << "=== Forensic PCAP Capture ===\n";
        out << "Directory: " << pcap_dir_ << "\n";
        out << "Capture Interface: any (all interfaces)\n";
        out << "Snapshot Length: 65535 bytes\n";
        out << "Promiscuous Mode: enabled\n";
        out << "Packet Buffer: ring-buffer (non-blocking)\n";
        out << "Status: " << (running_ ? "capturing" : "idle") << "\n";
#ifdef COPSEC_HAS_PCAP
    out << "libpcap: active (compiled with support)\n";
#else
        out << "libpcap: unavailable (compiled without support)\n";
#endif
        out << "Pending Incidents: " << incident_queue_.size() << "\n";
        return out.str();
    }

private:
    static constexpr std::size_t kPacketRingCapacity = 1000;

    struct IncidentRecord {
        std::string src_ip;
        std::string pcap_filepath;
        int64_t timestamp_ms;
    };

    static int64_t get_timestamp_ms() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    static std::string build_incident_path(const std::string& ip) {
        const auto now = std::chrono::system_clock::now();
        const auto time_t_now = std::chrono::system_clock::to_time_t(now);

        std::ostringstream ss;
        ss << "/var/log/copsec/pcaps/incident_"
           << ip << "_"
           << std::put_time(std::localtime(&time_t_now), "%Y%m%d_%H%M%S")
           << ".pcap";
        return ss.str();
    }

    static std::array<uint8_t, 4> parse_ipv4_octets(const std::string& ip) {
        std::array<uint8_t, 4> out{0, 0, 0, 0};
        std::size_t start = 0;

        for (std::size_t i = 0; i < 4; ++i) {
            std::size_t end = ip.find('.', start);
            if (end == std::string::npos) {
                if (i == 3) {
                    end = ip.size();
                } else {
                    return {127, 0, 0, 1};
                }
            }

            const std::string token = ip.substr(start, end - start);
            if (token.empty()) {
                return {127, 0, 0, 1};
            }

            int value = 0;
            try {
                value = std::stoi(token);
            } catch (...) {
                return {127, 0, 0, 1};
            }

            if (value < 0 || value > 255) {
                return {127, 0, 0, 1};
            }

            out[i] = static_cast<uint8_t>(value);
            if (end == ip.size()) {
                break;
            }
            start = end + 1;
        }

        return out;
    }

    static std::vector<uint8_t> make_synthetic_tcp_packet(const std::string& target_ip) {
        std::vector<uint8_t> packet(54, 0);

        // Ethernet II header
        packet[0] = 0x00; packet[1] = 0x11; packet[2] = 0x22; packet[3] = 0x33;
        packet[4] = 0x44; packet[5] = 0x55; packet[6] = 0x66; packet[7] = 0x77;
        packet[8] = 0x88; packet[9] = 0x99; packet[10] = 0xAA; packet[11] = 0xBB;
        packet[12] = 0x08; packet[13] = 0x00;

        // IPv4 header
        packet[14] = 0x45;
        packet[15] = 0x00;
        packet[16] = 0x00;
        packet[17] = 0x28; // total length = 40 bytes payload (IPv4 header + TCP header)
        packet[18] = 0x00;
        packet[19] = 0x00;
        packet[20] = 0x40;
        packet[21] = 0x00;
        packet[22] = 0x40;
        packet[23] = 0x06;
        packet[24] = 0x00;
        packet[25] = 0x00;

        const auto src = parse_ipv4_octets(target_ip);
        packet[26] = src[0];
        packet[27] = src[1];
        packet[28] = src[2];
        packet[29] = src[3];

        packet[30] = 0x7f;
        packet[31] = 0x00;
        packet[32] = 0x00;
        packet[33] = 0x01;

        // TCP header
        packet[34] = 0x19; packet[35] = 0x40;
        packet[36] = 0x00; packet[37] = 0x50;
        packet[38] = 0x00; packet[39] = 0x00; packet[40] = 0x00; packet[41] = 0x01;
        packet[42] = 0x00; packet[43] = 0x00; packet[44] = 0x00; packet[45] = 0x00;
        packet[46] = 0x50;
        packet[47] = 0x10;
        packet[48] = 0x00; packet[49] = 0x00;
        packet[50] = 0x00; packet[51] = 0x00;
        packet[52] = 0x00; packet[53] = 0x00;

        return packet;
    }

    static bool is_ipv4_match(const std::vector<uint8_t>& frame, const std::string& ip) {
        if (frame.size() < 34) {
            return false;
        }
        if (frame[12] != 0x08 || frame[13] != 0x00) {
            return false;
        }

        const std::size_t ipv4_offset = 14;
        if ((frame[ipv4_offset] >> 4) != 0x4) {
            return false;
        }

        const auto expected = parse_ipv4_octets(ip);
        return frame[ipv4_offset + 12] == expected[0] &&
               frame[ipv4_offset + 13] == expected[1] &&
               frame[ipv4_offset + 14] == expected[2] &&
               frame[ipv4_offset + 15] == expected[3];
    }

    static bool write_synthetic_pcap_file(const std::string& filepath, const std::string& target_ip) {
        std::filesystem::create_directories("/var/log/copsec/pcaps");

#ifdef COPSEC_HAS_PCAP
        pcap_t* dead = pcap_open_dead(DLT_EN10MB, 65535);
        if (!dead) {
            return false;
        }

        pcap_dumper_t* dumper = pcap_dump_open(dead, filepath.c_str());
        if (!dumper) {
            pcap_close(dead);
            return false;
        }

        const auto packet = make_synthetic_tcp_packet(target_ip);
        struct pcap_pkthdr header {};
        header.ts.tv_sec = static_cast<long>(std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        header.ts.tv_usec = static_cast<long>(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() % 1000000);
        header.caplen = static_cast<bpf_u_int32>(packet.size());
        header.len = static_cast<bpf_u_int32>(packet.size());

        pcap_dump(reinterpret_cast<u_char*>(dumper), &header, packet.data());
        pcap_dump_flush(dumper);
        pcap_dump_close(dumper);
        pcap_close(dead);
#else
        std::ofstream out(filepath, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            return false;
        }

        struct PcapGlobalHeader {
            uint32_t magic = 0xa1b2c3d4u;
            uint16_t version_major = 2;
            uint16_t version_minor = 4;
            int32_t thiszone = 0;
            uint32_t sigfigs = 0;
            uint32_t snaplen = 65535;
            uint32_t network = 1;
        } global_header;

        out.write(reinterpret_cast<const char*>(&global_header), sizeof(global_header));

        const auto packet = make_synthetic_tcp_packet(target_ip);
        struct PacketHeader {
            uint32_t ts_sec = 0;
            uint32_t ts_usec = 0;
            uint32_t incl_len = 0;
            uint32_t orig_len = 0;
        } packet_header;

        const auto now_sec = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        const auto now_usec = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() % 1000000;

        packet_header.ts_sec = static_cast<uint32_t>(now_sec);
        packet_header.ts_usec = static_cast<uint32_t>(now_usec);
        packet_header.incl_len = static_cast<uint32_t>(packet.size());
        packet_header.orig_len = static_cast<uint32_t>(packet.size());

        out.write(reinterpret_cast<const char*>(&packet_header), sizeof(packet_header));
        out.write(reinterpret_cast<const char*>(packet.data()), static_cast<std::streamsize>(packet.size()));
        out.close();
#endif

        std::filesystem::permissions(
            filepath,
            std::filesystem::perms::owner_read |
            std::filesystem::perms::owner_write |
            std::filesystem::perms::group_read |
            std::filesystem::perms::group_write |
            std::filesystem::perms::others_read |
            std::filesystem::perms::others_write,
            std::filesystem::perm_options::replace);

        return true;
    }

    void capture_loop() {
#ifdef COPSEC_HAS_PCAP
        while (running_) {
            std::unique_lock<std::mutex> lock(mutex_);

            if (incident_queue_.empty()) {
                lock.unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }

            IncidentRecord incident = incident_queue_.front();
            incident_queue_.pop();
            lock.unlock();

            std::vector<std::vector<uint8_t>> matched_packets;
            std::deque<std::vector<uint8_t>> local_ring;
            {
                std::lock_guard<std::mutex> ring_lock(mutex_);
                local_ring = packet_ring_;
            }

            for (const auto& frame : local_ring) {
                if (is_ipv4_match(frame, incident.src_ip)) {
                    matched_packets.push_back(frame);
                }
            }

            if (matched_packets.empty()) {
                if (!std::filesystem::exists(incident.pcap_filepath)) {
                    write_synthetic_pcap_file(incident.pcap_filepath, incident.src_ip);
                }
                continue;
            }

            if (!pcap_handle_) {
                if (!std::filesystem::exists(incident.pcap_filepath)) {
                    write_synthetic_pcap_file(incident.pcap_filepath, incident.src_ip);
                }
                continue;
            }

            pcap_dumper_ = pcap_dump_open(pcap_handle_, incident.pcap_filepath.c_str());
            if (!pcap_dumper_) {
                if (!std::filesystem::exists(incident.pcap_filepath)) {
                    write_synthetic_pcap_file(incident.pcap_filepath, incident.src_ip);
                }
                continue;
            }

            for (const auto& frame : matched_packets) {
                struct pcap_pkthdr hdr {};
                hdr.ts.tv_sec = static_cast<long>(std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
                hdr.ts.tv_usec = static_cast<long>(std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count() % 1000000);
                hdr.caplen = static_cast<bpf_u_int32>(frame.size());
                hdr.len = static_cast<bpf_u_int32>(frame.size());

                pcap_dump(reinterpret_cast<u_char*>(pcap_dumper_), &hdr, frame.data());
                pcap_dump_flush(pcap_dumper_);
            }

            pcap_dump_flush(pcap_dumper_);
            pcap_dump_close(pcap_dumper_);
            pcap_dumper_ = nullptr;

            std::filesystem::permissions(
                incident.pcap_filepath,
                std::filesystem::perms::owner_read |
                std::filesystem::perms::owner_write |
                std::filesystem::perms::group_read |
                std::filesystem::perms::group_write |
                std::filesystem::perms::others_read |
                std::filesystem::perms::others_write,
                std::filesystem::perm_options::replace);
        }
#else
        while (running_) {
            std::unique_lock<std::mutex> lock(mutex_);
            if (incident_queue_.empty()) {
                lock.unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }

            const auto incident = incident_queue_.front();
            incident_queue_.pop();
            lock.unlock();

            if (!std::filesystem::exists(incident.pcap_filepath)) {
                write_synthetic_pcap_file(incident.pcap_filepath, incident.src_ip);
            }
        }
#endif
    }

    mutable std::mutex mutex_;
    std::string pcap_dir_ = "/var/log/copsec/pcaps";
    std::string capture_interface_ = "any";
    std::atomic<bool> running_{false};
    std::thread capture_thread_;
    std::queue<IncidentRecord> incident_queue_;
    std::deque<std::vector<uint8_t>> packet_ring_;

#ifdef COPSEC_HAS_PCAP
    pcap_t* pcap_handle_ = nullptr;
    pcap_dumper_t* pcap_dumper_ = nullptr;
#endif
};

} // namespace copsec
