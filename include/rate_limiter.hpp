#pragma once

#include <chrono>
#include <cstddef>
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

private:
    using Timestamp = std::chrono::steady_clock::time_point;

    Bouncer& bouncer_;
    ShmServer& shm_server_;
    std::unordered_map<std::string, std::vector<Timestamp>> requests_;
    std::mutex mutex_;
};

} // namespace copsec
