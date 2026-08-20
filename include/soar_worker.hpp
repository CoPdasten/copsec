#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

namespace copsec {

class Bouncer;

class SoarWorker {
public:
    struct Settings {
        std::string abuse_api_url = "https://api.abuseipdb.com/api/v2/check";
        std::string tor_exit_url = "https://check.torproject.org/torbulkexitlist";
        std::string c2_url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt";
        std::chrono::hours refresh_period{12};
        std::chrono::seconds request_timeout{20};
    };

    explicit SoarWorker(Bouncer& bouncer);
    SoarWorker(Bouncer& bouncer, Settings settings);
    ~SoarWorker();

    SoarWorker(const SoarWorker&) = delete;
    SoarWorker& operator=(const SoarWorker&) = delete;

    bool start();
    void stop();
    void on_ban_decision(std::string ip, int duration_seconds, std::string rule_id);

private:
    struct BanRequest {
        std::string ip;
        int duration_seconds;
        std::string rule_id;
    };

    void run();
    void refresh_lists();
    void process_ban(const BanRequest& request);
    std::string fetch(const std::string& url, const std::vector<std::string>& headers = {}) const;
    int abuse_confidence(const std::string& ip) const;
    static std::vector<std::string> parse_ip_list(const std::string& body);

    Bouncer& bouncer_;
    Settings settings_;
    std::atomic<bool> running_{false};
    std::thread thread_;
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    std::queue<BanRequest> queue_;
    std::chrono::steady_clock::time_point next_refresh_{};
};

} // namespace copsec