#include "logger.hpp"
#include <iostream>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <nlohmann/json.hpp>
#include <unistd.h>

namespace copsec {

Logger::Logger() : m_hostname("unknown-host"), m_running(false) {}

Logger::~Logger() {
    shutdown();
}

Logger& Logger::get_instance() {
    static Logger instance;
    return instance;
}

void Logger::init(const std::string& log_file_path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_running) return;

    m_log_path = log_file_path;

    // Detect system hostname using POSIX gethostname
    char hostname_buf[256];
    if (gethostname(hostname_buf, sizeof(hostname_buf)) == 0) {
        m_hostname = std::string(hostname_buf);
    }

    try {
        std::filesystem::path p(m_log_path);
        if (p.has_parent_path()) {
            std::filesystem::create_directories(p.parent_path());
        }
        m_log_file.open(m_log_path, std::ios::out | std::ios::app);
        if (!m_log_file.is_open()) {
            std::cerr << "[Logger Error] Failed to open log file: " << m_log_path << ". Logging to stdout only." << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "[Logger Error] Exception creating log file path: " << e.what() << ". Logging to stdout only." << std::endl;
    }

    m_running = true;
    m_worker = std::thread(&Logger::process_queue, this);
}

void Logger::shutdown() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_running) return;
        m_running = false;
    }
    m_cv.notify_all();

    if (m_worker.joinable()) {
        m_worker.join();
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_log_file.is_open()) {
        m_log_file.close();
    }
}

void Logger::log(LogLevel level, const std::string& event_type, const std::string& message,
                 const std::string& severity, const std::string& action_taken,
                 const std::string& ip, const std::string& rule_id,
                 const std::string& rule_name, int trigger_count, int time_window_sec,
                 const std::string& mitre_tactic, const std::string& mitre_tactic_id,
                 const std::string& mitre_technique_id, const std::string& mitre_technique_name,
                 const std::string& mitre_url, const std::string& log_source,
                 const std::string& raw_sample, const std::string& event_category) {
    LogEvent log_event{
        get_iso8601_timestamp(),
        level,
        event_category,
        event_type,
        severity,
        action_taken,
        ip,
        rule_id,
        rule_name,
        trigger_count,
        time_window_sec,
        mitre_tactic,
        mitre_tactic_id,
        mitre_technique_id,
        mitre_technique_name,
        mitre_url,
        log_source,
        raw_sample,
        message
    };

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_running) {
            // Process-direct output if log queue not running or stopped
            nlohmann::json j;
            j["timestamp"] = log_event.timestamp;
            j["version"] = "1.0.0";
            j["agent"] = {
                {"hostname", m_hostname},
                {"id", "copsec-agent"}
            };
            j["event"] = {
                {"category", log_event.event_category},
                {"type", log_event.event_type},
                {"severity", log_event.severity}
            };
            if (!log_event.action_taken.empty()) {
                j["event"]["action_taken"] = log_event.action_taken;
            }
            if (!log_event.message.empty()) {
                j["message"] = log_event.message;
            }
            if (!log_event.ip.empty()) {
                j["source"] = {{"ip", log_event.ip}};
            }
            if (!log_event.rule_id.empty()) {
                j["rule"] = {
                    {"id", log_event.rule_id},
                    {"name", log_event.rule_name},
                    {"trigger_count", log_event.trigger_count},
                    {"time_window_sec", log_event.time_window_sec}
                };
            }
            if (!log_event.mitre_technique_id.empty()) {
                j["mitre_attack"] = {
                    {"tactic", log_event.mitre_tactic},
                    {"tactic_id", log_event.mitre_tactic_id},
                    {"technique_id", log_event.mitre_technique_id},
                    {"technique_name", log_event.mitre_technique_name},
                    {"url", log_event.mitre_url}
                };
            }
            if (!log_event.raw_sample.empty()) {
                j["evidence"] = {
                    {"log_source", log_event.log_source},
                    {"raw_sample", log_event.raw_sample}
                };
            }
            std::cout << j.dump() << std::endl;
            return;
        }
        m_queue.push(std::move(log_event));
    }
    m_cv.notify_one();
}

void Logger::process_queue() {
    while (true) {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_cv.wait(lock, [this]() {
            return !m_queue.empty() || !m_running;
        });

        if (m_queue.empty() && !m_running) {
            break;
        }

        while (!m_queue.empty()) {
            LogEvent event = std::move(m_queue.front());
            m_queue.pop();

            // Unlock during filesystem operations to avoid thread blocking
            lock.unlock();

            nlohmann::json j;
            j["timestamp"] = event.timestamp;
            j["version"] = "1.0.0";
            j["agent"] = {
                {"hostname", m_hostname},
                {"id", "copsec-agent"}
            };
            j["event"] = {
                {"category", event.event_category},
                {"type", event.event_type},
                {"severity", event.severity}
            };
            if (!event.action_taken.empty()) {
                j["event"]["action_taken"] = event.action_taken;
            }
            if (!event.message.empty()) {
                j["message"] = event.message;
            }
            if (!event.ip.empty()) {
                j["source"] = {{"ip", event.ip}};
            }
            if (!event.rule_id.empty()) {
                j["rule"] = {
                    {"id", event.rule_id},
                    {"name", event.rule_name},
                    {"trigger_count", event.trigger_count},
                    {"time_window_sec", event.time_window_sec}
                };
            }
            if (!event.mitre_technique_id.empty()) {
                j["mitre_attack"] = {
                    {"tactic", event.mitre_tactic},
                    {"tactic_id", event.mitre_tactic_id},
                    {"technique_id", event.mitre_technique_id},
                    {"technique_name", event.mitre_technique_name},
                    {"url", event.mitre_url}
                };
            }
            if (!event.raw_sample.empty()) {
                j["evidence"] = {
                    {"log_source", event.log_source},
                    {"raw_sample", event.raw_sample}
                };
            }

            std::string serialized = j.dump();

            // Direct output to terminal
            std::cout << serialized << std::endl;

            // Direct output to active system logs
            if (m_log_file.is_open()) {
                m_log_file << serialized << "\n";
                m_log_file.flush();
            }

            lock.lock();
        }
    }
}

std::string Logger::get_iso8601_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::stringstream ss;
    struct tm buf;
    if (gmtime_r(&time, &buf)) {
        ss << std::put_time(&buf, "%Y-%m-%dT%H:%M:%S")
           << '.' << std::setfill('0') << std::setw(3) << ms.count()
           << 'Z';
    }
    return ss.str();
}

std::string Logger::log_level_to_string(LogLevel level) {
    switch (level) {
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARN: return "WARN";
        case LogLevel::ERR:  return "ERROR";
    }
    return "UNKNOWN";
}

} // namespace copsec
