#include "penalty_engine.hpp"
#include "bouncer.hpp"
#include "db_manager.hpp"
#include "shm_ipc.hpp"
#include "logger.hpp"
#include "siem_exporter.hpp"

#include <algorithm>

namespace copsec {

PenaltyEngine::PenaltyEngine(Bouncer& bouncer, ShmServer& shm_server)
    : bouncer_(bouncer), shm_server_(shm_server) {}

const char* PenaltyEngine::risk_for(int score) {
    if (score >= 100) return "CRITICAL";
    if (score >= 60) return "HIGH";
    if (score >= 30) return "SUSPICIOUS";
    return "LOW";
}

void PenaltyEngine::decay_locked(std::chrono::system_clock::time_point now) {
    for (auto it = scores_.begin(); it != scores_.end();) {
        auto& entry = it->second;
        if (entry.last_activity.time_since_epoch().count() != 0) {
            const auto hours = std::chrono::duration_cast<std::chrono::hours>(now - entry.last_activity).count();
            if (hours > 0) {
                entry.score = std::max(0, entry.score - static_cast<int>(hours) * 10);
                entry.last_activity += std::chrono::hours(hours);
            }
        }
        if (entry.score == 0) it = scores_.erase(it);
        else ++it;
    }
}

void PenaltyEngine::score_only(const std::string& ip, int points) {
    if (ip.empty() || points <= 0) return;
    const auto now = std::chrono::system_clock::now();
    int score = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        decay_locked(now);
        auto& entry = scores_[ip];
        entry.score = std::min(100, entry.score + points);
        entry.last_activity = now;
        entry.risk = risk_for(entry.score);
        score = entry.score;
    }
    DbManager::get_instance().record_threat_score(ip, points);
    shm_server_.increment_threats(1);
    if (score >= 30) {
        Logger::get_instance().log(LogLevel::WARN, "THREAT_SCORE", "IP " + ip + " score=" + std::to_string(score) + " risk=" + risk_for(score), "HIGH", "tracked", ip, "adaptive-penalty");
    }
}

bool PenaltyEngine::record(const std::string& ip, int points, const std::string& rule_id,
                           const std::string& raw_payload) {
    if (ip.empty() || points <= 0) return false;
    score_only(ip, points);
    int score = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        score = scores_[ip].score;
    }
    if (score < 60) return false;
    const int duration = score >= 100 ? 86400 : 900;
    const bool banned = bouncer_.ban_ip(ip, duration, rule_id, raw_payload);
    if (banned) {
        SiemExporter::instance().export_event("BAN_DECISION", "Adaptive penalty ban", score >= 100 ? 10 : 7,
            ip, "BAN", "rule=" + rule_id + " duration=" + std::to_string(duration));
    }
    return banned;
}

std::vector<std::pair<std::string, PenaltyScore>> PenaltyEngine::active_scores() const {
    std::lock_guard<std::mutex> lock(mutex_);
    const_cast<PenaltyEngine*>(this)->decay_locked(std::chrono::system_clock::now());
    std::vector<std::pair<std::string, PenaltyScore>> result(scores_.begin(), scores_.end());
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        return left.second.score > right.second.score;
    });
    return result;
}

} // namespace copsec
