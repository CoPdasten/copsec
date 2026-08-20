#ifndef CONSENSUS_HPP
#define CONSENSUS_HPP

#include <string>
#include <unordered_map>
#include <set>
#include <vector>
#include <mutex>
#include <chrono>

struct ThreatEvent {
    std::string source_agent;
    std::string rule_id;
    std::string mitre_id;
    std::chrono::system_clock::time_point timestamp;
};

struct IPReputation {
    std::string ip;
    int total_score{0};
    std::set<std::string> reporting_agents;
    bool is_globally_banned{false};
    std::chrono::system_clock::time_point banned_at;
};

class ConsensusEngine {
private:
    std::unordered_map<std::string, IPReputation> ip_table;
    std::mutex mtx;
    const int GLOBAL_BAN_THRESHOLD = 3;

public:
    void process_telemetry(const std::string& ip, const std::string& agent_id, const std::string& rule_id) {
        std::lock_guard<std::mutex> lock(mtx);
        (void)rule_id; // Unused parameter warning engelleme
        
        auto& rep = ip_table[ip];
        rep.ip = ip;
        rep.reporting_agents.insert(agent_id);
        
        rep.total_score = static_cast<int>(rep.reporting_agents.size()) * 35;

        if (rep.total_score >= 100 || rep.reporting_agents.size() >= static_cast<size_t>(GLOBAL_BAN_THRESHOLD)) {
            if (!rep.is_globally_banned) {
                rep.is_globally_banned = true;
                rep.banned_at = std::chrono::system_clock::now();
            }
        }
    }

    std::vector<std::string> get_global_blocklist() {
        std::lock_guard<std::mutex> lock(mtx);
        std::vector<std::string> blocklist;
        
        for (const auto& [ip, rep] : ip_table) {
            if (rep.is_globally_banned) {
                blocklist.push_back(ip);
            }
        }
        return blocklist;
    }
};

#endif // CONSENSUS_HPP