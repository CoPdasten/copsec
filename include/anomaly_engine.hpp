#pragma once

#include <chrono>
#include <cstddef>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>

namespace copsec {

class PenaltyEngine;
class ShmServer;

class AnomalyEngine {
public:
    AnomalyEngine(PenaltyEngine& penalty_engine, ShmServer& shm_server);
    void evaluate_http(const std::string& ip, const std::string& payload,
                       const std::string& raw_line);
    static double shannon_entropy(const std::string& value);

private:
    using Clock = std::chrono::steady_clock;
    struct Window {
        std::deque<Clock::time_point> responses;
    };
    PenaltyEngine& penalty_engine_;
    ShmServer& shm_server_;
    std::mutex mutex_;
    std::unordered_map<std::string, Window> response_windows_;
};

} // namespace copsec
