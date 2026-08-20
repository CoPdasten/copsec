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

namespace copsec {

class ShmServer;

struct Rule {
    std::string id;
    std::string name;
    std::string log_file;
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
};

class LogWatcher {
public:
    LogWatcher(Bouncer& bouncer, ShmServer& shm_server);
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

    // Rate Limiter with trigger count output parameter
    bool check_rate_limit(const std::string& rule_id, const std::string& ip, int max_retry, int find_time, int& current_count);

    Bouncer& m_bouncer;
    ShmServer& m_shm_server;
    DetectionEngine m_detection_engine;
    std::vector<Rule> m_rules;

    // Inotify & watch state mappings
    int m_inotify_fd;
    std::thread m_watcher_thread;
    std::atomic<bool> m_running;

    std::unordered_map<int, FileState> m_watched_files;
    std::unordered_map<std::string, int> m_path_to_wd;
    std::unordered_map<int, std::filesystem::path> m_directory_wds;

    mutable std::mutex m_watch_mutex;

    // Sliding Window Rate Limiter
    std::unordered_map<std::string, std::vector<std::chrono::system_clock::time_point>> m_rate_limiter;
    std::mutex m_limiter_mutex;
};

} // namespace copsec
