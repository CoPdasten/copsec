#pragma once

#include <string>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <fstream>

namespace copsec {

enum class LogLevel {
    INFO,
    WARN,
    ERR
};

struct LogEvent {
    std::string timestamp;
    LogLevel level;
    std::string event_category;
    std::string event_type;
    std::string severity;
    std::string action_taken;
    std::string ip;
    std::string rule_id;
    std::string rule_name;
    int trigger_count;
    int time_window_sec;
    std::string mitre_tactic;
    std::string mitre_tactic_id;
    std::string mitre_technique_id;
    std::string mitre_technique_name;
    std::string mitre_url;
    std::string log_source;
    std::string raw_sample;
    std::string message; // for general system logs
};

class Logger {
public:
    static Logger& get_instance();

    // Disable copy and move operations
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    Logger(Logger&&) = delete;
    Logger& operator=(Logger&&) = delete;

    // Initializes the logger. Default is /var/log/copsec/agent.log
    void init(const std::string& log_file_path = "/var/log/copsec/agent.log");

    // Stops the logger and joins the worker thread
    void shutdown();

    // Logs a structured event
    void log(LogLevel level, const std::string& event_type, const std::string& message = "",
             const std::string& severity = "INFO", const std::string& action_taken = "",
             const std::string& ip = "", const std::string& rule_id = "",
             const std::string& rule_name = "", int trigger_count = 0, int time_window_sec = 0,
             const std::string& mitre_tactic = "", const std::string& mitre_tactic_id = "",
             const std::string& mitre_technique_id = "", const std::string& mitre_technique_name = "",
             const std::string& mitre_url = "", const std::string& log_source = "",
             const std::string& raw_sample = "", const std::string& event_category = "system");

private:
    Logger();
    ~Logger();

    // Worker thread function to write logs asynchronously
    void process_queue();

    // Formats current time as ISO8601 UTC
    std::string get_iso8601_timestamp();

    // Converts LogLevel enum to string representation
    std::string log_level_to_string(LogLevel level);

    std::string m_log_path;
    std::ofstream m_log_file;
    std::string m_hostname;

    std::queue<LogEvent> m_queue;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::atomic<bool> m_running;
    std::thread m_worker;
};

} // namespace copsec
