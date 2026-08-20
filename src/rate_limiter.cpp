#include "rate_limiter.hpp"

#include "bouncer.hpp"
#include "shm_ipc.hpp"

#include <algorithm>
#include <chrono>

namespace copsec {

RateLimiter::RateLimiter(Bouncer& bouncer, ShmServer& shm_server)
    : bouncer_(bouncer), shm_server_(shm_server) {}

bool RateLimiter::check_rate_limit(const std::string& ip,
                                   std::size_t max_requests,
                                   std::chrono::seconds window) {
    if (ip.empty() || max_requests == 0 || window <= std::chrono::seconds::zero()) {
        return false;
    }

    const auto now = std::chrono::steady_clock::now();
    const auto cutoff = now - window;
    bool exceeded = false;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& timestamps = requests_[ip];
        timestamps.erase(
            std::remove_if(timestamps.begin(), timestamps.end(),
                           [cutoff](const Timestamp timestamp) { return timestamp <= cutoff; }),
            timestamps.end());

        timestamps.push_back(now);
        exceeded = timestamps.size() > max_requests;
        if (exceeded) {
            timestamps.clear();
        }
    }

    if (!exceeded) {
        return false;
    }

    shm_server_.increment_threats(1);
    shm_server_.push_event(ip, "rate-limit-exceeded", 3600, "Impact", "T1499");
    bouncer_.ban_ip(ip, 3600, "rate-limit-exceeded");
    return true;
}

} // namespace copsec
