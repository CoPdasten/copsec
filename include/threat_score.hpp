#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>

namespace copsec {

class Bouncer;

struct ThreatScoreResult {
    int score = 0;
    bool threshold_crossed = false;
};

class ThreatScoreAccumulator {
public:
    static constexpr int kBanThreshold = 100;
    static constexpr int kLowSeverityPoints = 20;
    static constexpr int kHighSeverityPoints = 50;
    static constexpr std::chrono::seconds kWindow{300};

    ThreatScoreResult add_hit(const std::string& ip, int points,
                              std::chrono::system_clock::time_point now = std::chrono::system_clock::now());
    int score(const std::string& ip,
              std::chrono::system_clock::time_point now = std::chrono::system_clock::now());
    void clear(const std::string& ip);

private:
    struct Hit {
        std::chrono::system_clock::time_point timestamp;
        int points;
    };

    using History = std::deque<Hit>;
    void expire_locked(History& history, std::chrono::system_clock::time_point now) const;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, History> scores_;
};

class DetectionEngine {
public:
    explicit DetectionEngine(Bouncer& bouncer);

    bool record_hit(const std::string& ip, int points, int ban_duration_seconds,
                    const std::string& rule_id);
    ThreatScoreResult score_hit(const std::string& ip, int points);

private:
    Bouncer& bouncer_;
    ThreatScoreAccumulator accumulator_;
};

} // namespace copsec
