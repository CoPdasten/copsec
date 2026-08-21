#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include "threat_score.hpp"

namespace copsec {

class Bouncer;
class ShmServer;

struct PenaltyScore {
    int score = 0;
    std::string risk;
    std::chrono::system_clock::time_point last_activity{};
};

class PenaltyEngine {
public:
    PenaltyEngine(Bouncer& bouncer, ShmServer& shm_server);
    bool record(const std::string& ip, int points, const std::string& rule_id,
                const std::string& raw_payload = {});
    void score_only(const std::string& ip, int points);
    std::vector<std::pair<std::string, PenaltyScore>> active_scores() const;
    static const char* risk_for(int score);

private:
    void decay_locked(std::chrono::system_clock::time_point now);
    Bouncer& bouncer_;
    ShmServer& shm_server_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, PenaltyScore> scores_;
};

} // namespace copsec
