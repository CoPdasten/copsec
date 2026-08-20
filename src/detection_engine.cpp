#include "threat_score.hpp"

#include "bouncer.hpp"
#include "db_manager.hpp"

#include <algorithm>

namespace copsec {

void ThreatScoreAccumulator::expire_locked(History& history,
                                            std::chrono::system_clock::time_point now) const {
    while (!history.empty() && now - history.front().timestamp >= kWindow) {
        history.pop_front();
    }
}

ThreatScoreResult ThreatScoreAccumulator::add_hit(const std::string& ip, int points,
                                                    std::chrono::system_clock::time_point now) {
    if (ip.empty() || points <= 0) return {};

    std::lock_guard<std::mutex> lock(mutex_);
    auto& history = scores_[ip];
    expire_locked(history, now);
    int previous_score = 0;
    for (const auto& hit : history) previous_score += hit.points;
    history.push_back({now, points});
    const int new_score = previous_score + points;
    return {new_score, previous_score <= kBanThreshold && new_score > kBanThreshold};
}

int ThreatScoreAccumulator::score(const std::string& ip,
                                  std::chrono::system_clock::time_point now) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = scores_.find(ip);
    if (it == scores_.end()) return 0;
    expire_locked(it->second, now);
    if (it->second.empty()) scores_.erase(it);
    int total = 0;
    const auto refreshed = scores_.find(ip);
    if (refreshed != scores_.end()) {
        for (const auto& hit : refreshed->second) total += hit.points;
    }
    return total;
}

void ThreatScoreAccumulator::clear(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    scores_.erase(ip);
}

DetectionEngine::DetectionEngine(Bouncer& bouncer) : bouncer_(bouncer) {}

ThreatScoreResult DetectionEngine::score_hit(const std::string& ip, int points) {
    return accumulator_.add_hit(ip, points);
}

bool DetectionEngine::record_hit(const std::string& ip, int points, int ban_duration_seconds,
                                 const std::string& rule_id) {
    const auto result = score_hit(ip, points);
    if (!result.threshold_crossed || ip.empty() || DbManager::get_instance().is_whitelisted(ip)) {
        return false;
    }
    return bouncer_.ban_ip(ip, ban_duration_seconds, rule_id);
}

} // namespace copsec
