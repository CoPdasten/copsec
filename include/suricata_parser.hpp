#pragma once

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <ctime>
#include <fstream>
#include <functional>
#include <iomanip>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace copsec {

struct SuricataAlert {
    std::string src_ip;
    std::string dest_ip;
    std::string signature;
    uint32_t signature_id = 0;
    uint32_t severity = 3;
    std::string protocol;
    int64_t timestamp_ms = 0;
};

class SuricataWatcher {
public:
    explicit SuricataWatcher(const std::string& eve_path = "/var/log/suricata/eve.json")
        : eve_path_(eve_path), running_(false) {}

    ~SuricataWatcher() { stop(); }

    bool start(std::function<void(const SuricataAlert&)> callback) {
        callback_ = callback;
        running_ = true;
        watcher_thread_ = std::thread([this]() { watch_loop(); });
        return true;
    }

    void stop() {
        running_ = false;
        if (watcher_thread_.joinable()) {
            watcher_thread_.join();
        }
    }

private:
    void watch_loop() {
        std::ifstream input(eve_path_, std::ios::ate);
        if (!input.is_open()) {
            return;
        }

        input.seekg(0, std::ios::end);
        while (running_) {
            std::string line;
            while (std::getline(input, line)) {
                try {
                    const auto obj = nlohmann::json::parse(line);
                    if (obj.contains("event_type") && obj["event_type"] == "alert") {
                        SuricataAlert alert;
                        alert.src_ip = obj.value("src_ip", "");
                        alert.dest_ip = obj.value("dest_ip", "");
                        alert.protocol = obj.value("proto", "");
                        alert.timestamp_ms = extract_timestamp(obj);

                        if (obj.contains("alert")) {
                            const auto& alert_obj = obj["alert"];
                            alert.signature = alert_obj.value("signature", "");
                            alert.signature_id = alert_obj.value("signature_id", 0);
                            alert.severity = alert_obj.value("severity", 3);
                        }

                        if (!alert.src_ip.empty() && callback_) {
                            callback_(alert);
                        }
                    }
                } catch (const std::exception&) {
                    continue;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }

    static int64_t extract_timestamp(const nlohmann::json& obj) {
        if (obj.contains("timestamp")) {
            const std::string ts = obj["timestamp"].get<std::string>();
            try {
                const size_t dot_pos = ts.find('.');
                if (dot_pos != std::string::npos) {
                    const std::string ms_part = ts.substr(dot_pos + 1, 3);
                    std::tm tm{};
                    std::istringstream iss(ts.substr(0, dot_pos));
                    iss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
                    return std::mktime(&tm) * 1000 + std::stoi(ms_part);
                }
            } catch (...) {
            }
        }
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    std::string eve_path_;
    std::atomic<bool> running_;
    std::thread watcher_thread_;
    std::function<void(const SuricataAlert&)> callback_;
};

} // namespace copsec
