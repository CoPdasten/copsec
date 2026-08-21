#include "rate_limiter.hpp"

#include "bouncer.hpp"
#include "shm_ipc.hpp"

#include <algorithm>
#include <chrono>

namespace copsec {

RateLimiter::RateLimiter(Bouncer& bouncer, ShmServer& shm_server)
    : bouncer_(bouncer), shm_server_(shm_server) {
    for (auto& slot : http_slots_) {
        slot.key.store(0, std::memory_order_relaxed);
        slot.window_start_ms.store(0, std::memory_order_relaxed);
        slot.requests.store(0, std::memory_order_relaxed);
    }
}

bool RateLimiter::check_http_rate_limit(const std::string& ip) {
    if (ip.empty()) return false;
    uint64_t hash = 1469598103934665603ULL;
    for (const unsigned char character : ip) hash = (hash ^ character) * 1099511628211ULL;
    const uint64_t key = hash == 0 ? 1 : hash;
    auto& slot = http_slots_[key % kHttpSlots];
    uint64_t observed = slot.key.load(std::memory_order_acquire);
    if (observed != key && !slot.key.compare_exchange_strong(observed, key, std::memory_order_acq_rel)) {
        return false;
    }

    const uint64_t now_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    uint64_t start = slot.window_start_ms.load(std::memory_order_acquire);
    if (start == 0 || now_ms - start >= 1000) {
        if (slot.window_start_ms.compare_exchange_strong(start, now_ms, std::memory_order_acq_rel)) {
            slot.requests.store(0, std::memory_order_release);
        }
    }

    const uint32_t count = slot.requests.fetch_add(1, std::memory_order_acq_rel) + 1;
    if (count <= 30) return false;
    slot.requests.store(0, std::memory_order_release);
    shm_server_.increment_threats(1);
    shm_server_.push_event(ip, "http-flood-ddos", 86400, "Impact", "T1499", "Endpoint Denial of Service");
    bouncer_.ban_ip(ip, 86400, "http-flood-ddos", "HTTP request rate exceeded 30 requests per second");
    return true;
}

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
