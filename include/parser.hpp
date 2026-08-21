#pragma once

#include <string>
#include <vector>
#include <regex>
#include <chrono>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <nlohmann/json.hpp>
#include "bouncer.hpp"
#include "threat_score.hpp"
#include "rate_limiter.hpp"
#include "penalty_engine.hpp"
#include "anomaly_engine.hpp"
#include "decoy_engine.hpp"

namespace copsec {

class ShmServer;

struct Rule {
    std::string id;
    std::string name;
    std::string log_file;
    std::vector<std::string> log_files;
    std::string category;
    std::regex regex;
    std::vector<int> ip_group_indices;
    int max_retry;
    int find_time;      // in seconds
    int ban_time;       // in seconds
    std::string mitre_tactic;
    std::string mitre_tactic_id;
    std::string mitre_technique_id;
    std::string mitre_technique_name;
    std::string mitre_url;
    std::vector<std::string> mitre_tactics;
    std::vector<std::string> mitre_technique_ids;
    std::vector<std::string> mitre_technique_names;
};

class LogWatcher {
public:
    LogWatcher(Bouncer& bouncer, ShmServer& shm_server, DecoyEngine::Settings decoy_settings = {});
    ~LogWatcher();

    // Disable copy/move operations
    LogWatcher(const LogWatcher&) = delete;
    LogWatcher& operator=(const LogWatcher&) = delete;
    LogWatcher(LogWatcher&&) = delete;
    LogWatcher& operator=(LogWatcher&&) = delete;

    // Loads detection rules from a JSON object
    bool load_rules(const nlohmann::json& rules_json);

    // Atomically replaces the active rules and reconciles log watches.
    bool reload_rules(const nlohmann::json& rules_json);

    std::size_t rule_count() const;

    // Starts real-time inotify log watch thread
    bool start();

    // Stops log watch thread and releases file watch resources
    void stop();

private:
    struct FileState {
        std::string path;
        int wd;
        int fd;
        std::uint64_t read_offset;
        std::string pending_line;
    };

    // Thread work loop
    void run();

    // Event handlers
    void process_file_events(int wd);
    void read_new_lines(FileState& state);
    void handle_log_line(const std::string& file_path, const std::string& line);
    void add_file_watch(const std::string& path);
    void add_directory_watch(const std::filesystem::path& directory);
    void recover_file_watch(const std::string& path);
    void refresh_dynamic_watches();

    bool rule_matches_file(const Rule& rule, const std::string& file_path) const;
    bool handle_suricata_line(const std::string& file_path, const std::string& line);
    void record_suricata_alert(const std::string& ip, const std::string& signature,
                               std::uint32_t sid, std::uint32_t severity,
                               const std::string& raw_line);

    // Rate Limiter with trigger count output parameter
    bool check_rate_limit(const std::string& rule_id, const std::string& ip, int max_retry, int find_time, int& current_count);

    Bouncer& m_bouncer;
    ShmServer& m_shm_server;
    PenaltyEngine m_penalty_engine;
    AnomalyEngine m_anomaly_engine;
    DecoyEngine::Settings m_decoy_settings;
    DecoyEngine m_decoy_engine;
    RateLimiter m_http_rate_limiter;
    std::vector<Rule> m_rules;

    // Inotify & watch state mappings
    int m_inotify_fd;
    std::thread m_watcher_thread;
    std::atomic<bool> m_running;

    std::unordered_map<int, FileState> m_watched_files;
    std::unordered_map<std::string, int> m_path_to_wd;
    std::unordered_map<int, std::filesystem::path> m_directory_wds;
    std::vector<std::filesystem::path> m_monitored_paths;
    std::chrono::steady_clock::time_point m_next_discovery{};

    mutable std::mutex m_watch_mutex;

    // Sliding Window Rate Limiter
    std::unordered_map<std::string, std::vector<std::chrono::system_clock::time_point>> m_rate_limiter;
    std::mutex m_limiter_mutex;

    mutable std::mutex m_suricata_mutex;
    std::unordered_map<std::string, std::chrono::system_clock::time_point> m_suricata_recent;
    std::atomic<std::uint64_t> m_suricata_alerts{0};
};

} // namespace copsec
