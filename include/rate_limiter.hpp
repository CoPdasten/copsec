#pragma once

#include <chrono>
#include <cstddef>
#include <array>
#include <atomic>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace copsec {

class Bouncer;
class ShmServer;

class RateLimiter {
public:
    RateLimiter(Bouncer& bouncer, ShmServer& shm_server);

    bool check_rate_limit(const std::string& ip,
                          std::size_t max_requests,
                          std::chrono::seconds window);

    bool check_http_rate_limit(const std::string& ip);

private:
    using Timestamp = std::chrono::steady_clock::time_point;

    Bouncer& bouncer_;
    ShmServer& shm_server_;
    std::unordered_map<std::string, std::vector<Timestamp>> requests_;
    std::mutex mutex_;

    struct HttpSlot {
        std::atomic<uint64_t> key{0};
        std::atomic<uint64_t> window_start_ms{0};
        std::atomic<uint32_t> requests{0};
    };
    static constexpr std::size_t kHttpSlots = 4096;
    std::array<HttpSlot, kHttpSlots> http_slots_;
};

} // namespace copsec
