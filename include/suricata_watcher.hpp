#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

namespace copsec {

class Bouncer;
class RateLimiter;
class ShmServer;

struct SuricataAlert {
    std::string src_ip;
    std::string dest_ip;
    std::string signature;
    std::string category;
    std::uint32_t signature_id = 0;
    std::uint32_t severity = 3;
    std::string protocol;
    std::int64_t timestamp_ms = 0;
};

class SuricataWatcher {
public:
    explicit SuricataWatcher(Bouncer& bouncer,
                             ShmServer& shm_server,
                             RateLimiter& rate_limiter,
                             std::string eve_path = "/var/log/suricata/eve.json");
    ~SuricataWatcher();

    SuricataWatcher(const SuricataWatcher&) = delete;
    SuricataWatcher& operator=(const SuricataWatcher&) = delete;

    bool start();
    void stop();

private:
    void watch_loop();
    void handle_alert(const SuricataAlert& alert);

    Bouncer& bouncer_;
    ShmServer& shm_server_;
    RateLimiter& rate_limiter_;
    std::string eve_path_;
    std::atomic<bool> running_{false};
    std::thread watcher_thread_;
};

} // namespace copsec
