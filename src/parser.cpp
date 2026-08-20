#include "parser.hpp"
#include "logger.hpp"
#include "normalizer.hpp"
#include "honeypot.hpp"
#include "geoip.hpp"
#include "fail2ban_engine.hpp"
#include "shm_ipc.hpp"
#include <sys/inotify.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <algorithm>
#include <iostream>
#include <regex>

namespace copsec {

static Fail2banEngine g_fail2ban_engine;

// Convert named captures used by fail2ban-style rules to ECMAScript captures.
std::string transform_pattern(const std::string& pattern, std::vector<int>& ip_group_indices) {
    ip_group_indices.clear();
    std::string result;
    int group_count = 0;

    for (std::size_t i = 0; i < pattern.size();) {
        if (pattern.compare(i, 7, "(?P<ip>") == 0 || pattern.compare(i, 7, "(?<HOST") == 0) {
            const auto close = pattern.find('>', i);
            if (close != std::string::npos) {
                ip_group_indices.push_back(++group_count);
                result += '(';
                i = close + 1;
                continue;
            }
        }

        if (pattern[i] == '(') {
            const bool special = i + 2 < pattern.size() && pattern[i + 1] == '?' &&
                (pattern[i + 2] == ':' || pattern[i + 2] == '=' || pattern[i + 2] == '!');
            if (!special) ++group_count;
        }
        result += pattern[i++];
    }
    return result;
}

LogWatcher::LogWatcher(Bouncer& bouncer, ShmServer& shm_server)
        : m_bouncer(bouncer), m_shm_server(shm_server), m_detection_engine(bouncer),
            m_inotify_fd(-1), m_running(false) {}

LogWatcher::~LogWatcher() {
    stop();
}

bool LogWatcher::load_rules(const nlohmann::json& rules_json) {
    try {
        if (!rules_json.contains("rules") || !rules_json["rules"].is_array()) {
            Logger::get_instance().log(LogLevel::ERR, "CONFIG_ERROR", "rules.json is missing 'rules' array");
            return false;
        }

        for (const auto& rule_data : rules_json["rules"]) {
            Rule rule;
            rule.id = rule_data.value("id", "");
            rule.name = rule_data.value("name", "");
            rule.log_file = rule_data.value("log_file", "");
            std::string raw_pattern = rule_data.value("regex", rule_data.value("pattern", ""));
            rule.max_retry = rule_data.value("max_retry", 5);
            rule.find_time = rule_data.value("find_time", 60);
            rule.ban_time = rule_data.value("ban_duration", rule_data.value("ban_time", 3600));

            if (rule.id.empty() || rule.log_file.empty() || raw_pattern.empty()) {
                Logger::get_instance().log(LogLevel::ERR, "CONFIG_ERROR", "Invalid rule: missing id, log_file, or pattern");
                continue;
            }

            if (raw_pattern.rfind("(?i)", 0) == 0) raw_pattern.erase(0, 4);
            std::string parsed_regex = transform_pattern(raw_pattern, rule.ip_group_indices);

            try {
                // WAF Fix: icase flag added to match normalized lower-case strings cleanly
                rule.regex = std::regex(parsed_regex, 
                    std::regex_constants::ECMAScript | 
                    std::regex_constants::icase | 
                    std::regex_constants::optimize);
            } catch (const std::regex_error& e) {
                Logger::get_instance().log(LogLevel::ERR, "CONFIG_ERROR", "Regex compile error for rule " + rule.id + ": " + e.what());
                continue;
            }

            if (rule_data.contains("mitre_tactic") || rule_data.contains("mitre_technique")) {
                rule.mitre_tactic = rule_data.value("mitre_tactic", "");
                rule.mitre_technique_id = rule_data.value("mitre_technique", "");
            } else if (rule_data.contains("mitre")) {
                auto mitre = rule_data["mitre"];
                rule.mitre_tactic = mitre.value("tactic", "");
                rule.mitre_tactic_id = mitre.value("tactic_id", "");
                rule.mitre_technique_id = mitre.value("technique_id", "");
                rule.mitre_technique_name = mitre.value("technique_name", "");
                rule.mitre_url = mitre.value("url", "");
            }

            m_rules.push_back(rule);
            Logger::get_instance().log(LogLevel::INFO, "RULE_LOADED", "Rule loaded: " + rule.id + " -> " + rule.log_file);
        }
        return true;
    } catch (const std::exception& e) {
        Logger::get_instance().log(LogLevel::ERR, "CONFIG_ERROR", std::string("Exception parsing rules: ") + e.what());
        return false;
    }
}

bool LogWatcher::reload_rules(const nlohmann::json& rules_json) {
    LogWatcher candidate(m_bouncer, m_shm_server);
    if (!candidate.load_rules(rules_json)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_watch_mutex);
    for (auto& [wd, state] : m_watched_files) {
        inotify_rm_watch(m_inotify_fd, wd);
        if (state.fd >= 0) close(state.fd);
    }
    m_watched_files.clear();
    m_path_to_wd.clear();
    m_directory_wds.clear();
    m_rules = std::move(candidate.m_rules);

    for (const auto& rule : m_rules) {
        add_directory_watch(std::filesystem::path(rule.log_file).parent_path());
        add_file_watch(rule.log_file);
        if (rule.log_file == "/var/log/nginx/access.log") {
            const std::string apache_log = "/var/log/apache2/access.log";
            add_directory_watch(std::filesystem::path(apache_log).parent_path());
            add_file_watch(apache_log);
        }
    }
    return true;
}

std::size_t LogWatcher::rule_count() const {
    std::lock_guard<std::mutex> lock(m_watch_mutex);
    return m_rules.size();
}

bool LogWatcher::start() {
    if (m_running) return false;

    m_inotify_fd = inotify_init1(IN_NONBLOCK);
    if (m_inotify_fd < 0) {
        Logger::get_instance().log(LogLevel::ERR, "SYSTEM", "Failed to initialize inotify");
        return false;
    }

    std::lock_guard<std::mutex> lock(m_watch_mutex);

    for (const auto& rule : m_rules) {
        if (m_path_to_wd.find(rule.log_file) != m_path_to_wd.end()) {
            continue;
        }

        add_directory_watch(std::filesystem::path(rule.log_file).parent_path());
        add_file_watch(rule.log_file);

        if (rule.log_file == "/var/log/nginx/access.log") {
            const std::string apache_log = "/var/log/apache2/access.log";
            add_directory_watch(std::filesystem::path(apache_log).parent_path());
            add_file_watch(apache_log);
        }
    }

    m_running = true;
    m_watcher_thread = std::thread(&LogWatcher::run, this);
    return true;
}

void LogWatcher::stop() {
    if (!m_running) return;

    m_running = false;
    if (m_watcher_thread.joinable()) {
        m_watcher_thread.join();
    }

    std::lock_guard<std::mutex> lock(m_watch_mutex);
    for (auto& [wd, state] : m_watched_files) {
        inotify_rm_watch(m_inotify_fd, wd);
        if (state.fd >= 0) {
            close(state.fd);
            state.fd = -1;
        }
    }
    m_watched_files.clear();
    m_path_to_wd.clear();
    m_directory_wds.clear();

    if (m_inotify_fd >= 0) {
        close(m_inotify_fd);
        m_inotify_fd = -1;
    }
}

void LogWatcher::run() {
    struct pollfd pfd;
    pfd.fd = m_inotify_fd;
    pfd.events = POLLIN;

    char buffer[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));

    while (m_running) {
        int poll_res = poll(&pfd, 1, 100);
        if (poll_res < 0) {
            if (errno == EINTR) continue;
            Logger::get_instance().log(LogLevel::ERR, "SYSTEM", "poll() failed on inotify fd");
            break;
        }

        if (poll_res == 0) continue;

        if (pfd.revents & POLLIN) {
            ssize_t len = read(m_inotify_fd, buffer, sizeof(buffer));
            if (len < 0 && errno != EAGAIN) {
                Logger::get_instance().log(LogLevel::ERR, "SYSTEM", "read() failed on inotify fd");
                break;
            }

            if (len <= 0) continue;

            const struct inotify_event* event;
            for (char* ptr = buffer; ptr < buffer + len; ptr += sizeof(struct inotify_event) + event->len) {
                event = reinterpret_cast<const struct inotify_event*>(ptr);

                if (event->mask & (IN_CREATE | IN_MOVED_TO)) {
                    std::lock_guard<std::mutex> lock(m_watch_mutex);
                    const auto dir_it = m_directory_wds.find(event->wd);
                    if (dir_it != m_directory_wds.end() && event->len > 0) {
                        for (const auto& rule : m_rules) {
                            const auto path = std::filesystem::path(rule.log_file);
                            if (path.parent_path() == dir_it->second && path.filename() == event->name) {
                                add_file_watch(rule.log_file);
                            }
                        }
                    }
                } else if (event->mask & (IN_MODIFY | IN_ATTRIB)) {
                    process_file_events(event->wd);
                } else if (event->mask & (IN_IGNORED | IN_DELETE_SELF | IN_MOVE_SELF)) {
                    std::lock_guard<std::mutex> lock(m_watch_mutex);
                    auto it = m_watched_files.find(event->wd);
                    if (it != m_watched_files.end()) {
                        std::string path = it->second.path;
                        Logger::get_instance().log(LogLevel::WARN, "SYSTEM", "Log file rotated/deleted: " + path + ". Attempting recovery...");

                        m_path_to_wd.erase(path);
                        m_watched_files.erase(it);
                        recover_file_watch(path);
                    }
                }
            }
        }
    }
}

void LogWatcher::add_directory_watch(const std::filesystem::path& directory) {
    for (const auto& [wd, watched_directory] : m_directory_wds) {
        if (watched_directory == directory) return;
    }

    const int wd = inotify_add_watch(m_inotify_fd, directory.c_str(), IN_CREATE | IN_MOVED_TO);
    if (wd >= 0) {
        m_directory_wds[wd] = directory;
    } else {
        Logger::get_instance().log(LogLevel::WARN, "SYSTEM", "Failed to watch log directory " + directory.string() + ": " + strerror(errno));
    }
}

void LogWatcher::add_file_watch(const std::string& path) {
    if (m_path_to_wd.find(path) != m_path_to_wd.end() || !std::filesystem::is_regular_file(path)) return;

    const int wd = inotify_add_watch(m_inotify_fd, path.c_str(), IN_MODIFY | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF);
    if (wd < 0) return;

    const int fd = open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        inotify_rm_watch(m_inotify_fd, wd);
        return;
    }

    const off_t end = lseek(fd, 0, SEEK_END);
    if (end < 0) {
        close(fd);
        inotify_rm_watch(m_inotify_fd, wd);
        return;
    }

    FileState state;
    state.path = path;
    state.wd = wd;
    state.fd = fd;
    state.read_offset = static_cast<std::uint64_t>(end);
    m_watched_files[wd] = std::move(state);
    m_path_to_wd[path] = wd;
    Logger::get_instance().log(LogLevel::INFO, "SYSTEM", "Monitoring log file: " + path);
}

void LogWatcher::recover_file_watch(const std::string& path) {
    add_file_watch(path);
}

void LogWatcher::process_file_events(int wd) {
    std::lock_guard<std::mutex> lock(m_watch_mutex);
    auto it = m_watched_files.find(wd);
    if (it != m_watched_files.end()) {
        read_new_lines(it->second);
    }
}

void LogWatcher::read_new_lines(FileState& state) {
    if (state.fd < 0) {
        return;
    }

    struct stat file_stat {};
    if (fstat(state.fd, &file_stat) < 0) {
        return;
    }

    if (static_cast<std::uint64_t>(file_stat.st_size) < state.read_offset) {
        state.read_offset = 0;
        state.pending_line.clear();
        if (lseek(state.fd, 0, SEEK_SET) < 0) {
            return;
        }
    }

    char buffer[8192];
    for (;;) {
        const ssize_t bytes_read = read(state.fd, buffer, sizeof(buffer));
        if (bytes_read > 0) {
            state.read_offset += static_cast<std::uint64_t>(bytes_read);
            state.pending_line.append(buffer, static_cast<std::size_t>(bytes_read));

            std::size_t newline = 0;
            while ((newline = state.pending_line.find('\n')) != std::string::npos) {
                std::string line = state.pending_line.substr(0, newline);
                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }
                state.pending_line.erase(0, newline + 1);
                handle_log_line(state.path, line);
            }
            continue;
        }

        if (bytes_read == 0 || errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        Logger::get_instance().log(LogLevel::WARN, "SYSTEM", "Failed to read log file " + state.path + ": " + strerror(errno));
        break;
    }
}

void LogWatcher::handle_log_line(const std::string& file_path, const std::string& line) {
    m_shm_server.increment_processed_lines(1);
    // -------------------------------------------------------------
    // WAF ENHANCEMENT: Multi-Stage String Normalization
    // -------------------------------------------------------------
    std::string normalized_line = Normalizer::normalize(line);

    HoneypotEngine honeypot;
    std::string matched_trap;
    if (honeypot.is_honeypot_hit(normalized_line, matched_trap)) {
        std::string ip = "127.0.0.1";
        std::regex ip_regex(R"((\d{1,3}(?:\.\d{1,3}){3}|[A-Fa-f0-9:]+))");
        std::smatch ip_match;
        if (std::regex_search(normalized_line, ip_match, ip_regex)) {
            ip = ip_match[1].str();
        }

        Logger::get_instance().log(
            LogLevel::WARN,
            "HONEYPOT_HIT",
            "Decoy endpoint triggered: " + matched_trap + ". Threat score recorded.",
            "CRITICAL",
            "instant_ban",
            ip,
            "honeypot",
            "decoy-trap",
            0,
            86400,
            "deception",
            "TA0043",
            "T1083",
            "Decoy endpoint access",
            "https://attack.mitre.org/techniques/T1083/",
            file_path,
            line,
            "waf_honeypot"
        );

        if (ip != "127.0.0.1" && ip != "::1" && ip != "localhost") {
            m_detection_engine.record_hit(ip, ThreatScoreAccumulator::kHighSeverityPoints, 86400, "honeypot");
        }
        return;
    }

    for (const auto& rule : m_rules) {
        const bool apache_fallback = rule.log_file == "/var/log/nginx/access.log" &&
            file_path == "/var/log/apache2/access.log";
        if (rule.log_file != file_path && !apache_fallback) continue;

        std::smatch match;
        if (std::regex_search(normalized_line, match, rule.regex)) {
            std::string ip = "127.0.0.1";
            for (const int group_index : rule.ip_group_indices) {
                if (group_index < static_cast<int>(match.size()) && !match[group_index].str().empty()) {
                    ip = match[group_index].str();
                    break;
                }
            }

            if (rule.ip_group_indices.empty()) {
                std::smatch source_match;
                const std::regex source_ip_regex(R"((\d{1,3}(?:\.\d{1,3}){3}))");
                if (std::regex_search(normalized_line, source_match, source_ip_regex)) {
                    ip = source_match[1].str();
                }
            }

            const std::string rule_text = rule.id + " " + rule.name;
            const bool high_severity = rule_text.find("sqli") != std::string::npos ||
                rule_text.find("rce") != std::string::npos ||
                rule_text.find("injection") != std::string::npos ||
                rule_text.find("exploit") != std::string::npos;
            const int threat_points = high_severity ? ThreatScoreAccumulator::kHighSeverityPoints
                                                    : ThreatScoreAccumulator::kLowSeverityPoints;
            m_shm_server.increment_threats(1);
            m_shm_server.record_event(
                ip, rule.id, 0,
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count(),
                rule.mitre_tactic, rule.mitre_technique_id);

            GeoIPLookup geoip;
            const auto geo = geoip.lookup(ip);
            std::string geo_context = "geo=" + geo.country_code + ";asn=" + std::to_string(geo.asn);

            int current_count = 0;
            if (check_rate_limit(rule.id, ip, rule.max_retry, rule.find_time, current_count)) {
                const int escalated_ban_time = g_fail2ban_engine.evaluate_ip(ip, rule.ban_time, rule.find_time);
                const std::string subnet = g_fail2ban_engine.auto_aggregate_subnet_if_needed(ip, 600, 3);

                bool is_loopback = (ip == "127.0.0.1" || ip == "::1" || ip == "localhost");
                const bool ban_triggered = !is_loopback &&
                    m_detection_engine.record_hit(ip, threat_points, escalated_ban_time, rule.id);
                std::string action = is_loopback ? "skipped_lockout_prevention" :
                    (ban_triggered ? "nftables_drop" : "score_accumulating");
                std::string log_msg = is_loopback
                    ? "Security Alert: Rate limit exceeded for loopback. Skipping ban."
                    : (ban_triggered
                        ? "Threat Alert: Banning source IP " + ip + " for " + std::to_string(escalated_ban_time) + "s due to rule: " + rule.id + " (" + geo_context + ")"
                        : "Threat score recorded for source IP " + ip + "; cumulative threshold not reached for rule: " + rule.id);

                if (!subnet.empty()) {
                    log_msg += " | aggregated_subnet=" + subnet;
                }

                Logger::get_instance().log(
                    LogLevel::WARN,
                    "IP_BANNED",
                    log_msg,
                    "HIGH",
                    action,
                    ip,
                    rule.id,
                    rule.name,
                    current_count,
                    rule.find_time,
                    rule.mitre_tactic,
                    rule.mitre_tactic_id,
                    rule.mitre_technique_id,
                    rule.mitre_technique_name,
                    rule.mitre_url,
                    file_path,
                    line,
                    "threat_prevention"
                );

                if (!is_loopback) {
                    if (ban_triggered) {
                        Logger::get_instance().log(LogLevel::INFO, "BAN_SUCCESS",
                            "Successfully applied ban in nftables for IP: " + ip + " | ban_time=" + std::to_string(escalated_ban_time) + " | " + geo_context);
                    } else {
                        Logger::get_instance().log(LogLevel::ERR, "BAN_FAILURE",
                            "Failed or bypassed ban for IP: " + ip + " | " + geo_context);
                    }
                }
            } else {
                Logger::get_instance().log(
                    LogLevel::INFO,
                    "AUTH_FAILURE_ATTEMPT",
                    "Security Event: Matched pattern for rule " + rule.id + " (" + geo_context + ")",
                    "MEDIUM",
                    "logged",
                    ip,
                    rule.id,
                    rule.name,
                    current_count,
                    rule.find_time,
                    rule.mitre_tactic,
                    rule.mitre_tactic_id,
                    rule.mitre_technique_id,
                    rule.mitre_technique_name,
                    rule.mitre_url,
                    file_path,
                    line,
                    "threat_prevention"
                );
            }
        }
    }
}

bool LogWatcher::check_rate_limit(const std::string& rule_id, const std::string& ip, int max_retry, int find_time, int& current_count) {
    std::lock_guard<std::mutex> lock(m_limiter_mutex);
    auto now = std::chrono::system_clock::now();
    std::string key = rule_id + ":" + ip;

    auto& history = m_rate_limiter[key];

    history.erase(std::remove_if(history.begin(), history.end(),
        [now, find_time](const std::chrono::system_clock::time_point& tp) {
            return std::chrono::duration_cast<std::chrono::seconds>(now - tp).count() > find_time;
        }), history.end());

    history.push_back(now);
    current_count = static_cast<int>(history.size());

    if (current_count >= max_retry) {
        history.clear();
        return true;
    }

    return false;
}

} // namespace copsec