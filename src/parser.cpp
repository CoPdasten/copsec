#include "parser.hpp"
#include "logger.hpp"
#include "normalizer.hpp"
#include "honeypot.hpp"
#include "geoip.hpp"
#include "fail2ban_engine.hpp"
#include "shm_ipc.hpp"
#include "db_manager.hpp"
#include "siem_exporter.hpp"
#include "whitelist.hpp"
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
#include <iomanip>
#include <locale.h>
#include <set>

namespace copsec {

static Fail2banEngine g_fail2ban_engine;

namespace {

std::string fast_extract_ip_from_line(const std::string& line) {
    static const std::regex ip_fast_regex(
        R"((\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|::1|::ffff:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){1,7}\b))");
    std::smatch match;
    if (std::regex_search(line, match, ip_fast_regex)) {
        return match[1].str();
    }
    return "";
}

int fast_extract_http_status_code(const std::string& line) {
    static const std::regex status_regex(
        R"(\"(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT)\s+[^\s\"]+(?:\s+HTTP\/[0-9.]+)?\"\s+([1-5][0-9]{2})\b)",
        std::regex_constants::icase);
    std::smatch match;
    if (std::regex_search(line, match, status_regex)) {
        try {
            return std::stoi(match[1].str());
        } catch (...) {
            return 0;
        }
    }
    return 0;
}

bool is_pre_routing_whitelisted_ip(const std::string& ip) {
    if (ip.empty()) return false;
    if (WhitelistManager::is_fast_path_builtin(ip)) {
        return true;
    }
    if (DbManager::get_instance().is_whitelisted(ip)) {
        return true;
    }
    return false;
}

bool wildcard_match(const std::string& pattern, const std::string& value) {
    std::string expression = "^";
    for (const char character : pattern) {
        if (character == '*') expression += ".*";
        else if (character == '?') expression += '.';
        else if (std::string(".^$|()[]{}+\\").find(character) != std::string::npos) expression += '\\' + std::string(1, character);
        else expression += character;
    }
    expression += '$';
    try { return std::regex_match(value, std::regex(expression)); }
    catch (const std::regex_error&) { return false; }
}

bool is_web_log_path(const std::string& path) {
    const auto lower = [&path]() {
        std::string value = path;
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
        return value;
    }();
    return lower.find("nginx") != std::string::npos || lower.find("apache") != std::string::npos ||
        lower.find("access.log") != std::string::npos;
}

bool is_dynamic_log_candidate(const std::filesystem::path& path) {
    const std::string name = path.filename().string();
    const std::string lower = [&name]() {
        std::string value = name;
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
        return value;
    }();
    for (const auto& suffix : {std::string(".gz"), std::string(".xz"), std::string(".bz2"),
                               std::string(".zip"), std::string(".tar"), std::string(".1"),
                               std::string(".2")}) {
        if (lower.size() >= suffix.size() && lower.ends_with(suffix)) return false;
    }
    const auto extension = lower.ends_with(".log") || lower.ends_with(".json");
    const auto well_known = lower == "eve.json" || lower == "access.log" || lower == "error.log" ||
        lower == "audit.log" || lower == "messages" || lower == "syslog";
    return extension || well_known;
}

std::vector<std::string> watch_paths_for_rule(const Rule& rule) {
    std::vector<std::string> paths;
    for (const auto& target : rule.log_files) {
        if (target.find_first_of("*?") == std::string::npos) paths.push_back(target);
    }
    if (rule.category == "web" || rule.category == "sqli" || rule.category == "xss" ||
        rule.category == "rce" || rule.category == "lfi" || rule.category == "ssrf" ||
        std::any_of(rule.log_files.begin(), rule.log_files.end(), [](const std::string& path) {
            return path.find("*") != std::string::npos || path.find("?") != std::string::npos;
        })) {
        paths.insert(paths.end(), {
            "/var/log/nginx/access.log", "/var/log/apache2/access.log"
        });
    }
    std::sort(paths.begin(), paths.end());
    paths.erase(std::unique(paths.begin(), paths.end()), paths.end());
    return paths;
}

const std::vector<std::string>& default_suricata_paths() {
    static const std::vector<std::string> paths = {
        "/var/log/suricata/eve.json", "/var/log/suricata/fast.log"
    };
    return paths;
}

std::string url_decode(const std::string& input) {
    std::string decoded;
    decoded.reserve(input.size());
    for (std::size_t index = 0; index < input.size(); ++index) {
        if (input[index] == '%' && index + 2 < input.size()) {
            const auto hex = [](char character) -> int {
                if (character >= '0' && character <= '9') return character - '0';
                if (character >= 'a' && character <= 'f') return character - 'a' + 10;
                if (character >= 'A' && character <= 'F') return character - 'A' + 10;
                return -1;
            };
            const int high = hex(input[index + 1]);
            const int low = hex(input[index + 2]);
            if (high >= 0 && low >= 0) {
                decoded.push_back(static_cast<char>((high << 4) | low));
                index += 2;
                continue;
            }
        }
        decoded.push_back(input[index] == '+' ? ' ' : input[index]);
    }
    return decoded;
}

}

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

LogWatcher::LogWatcher(Bouncer& bouncer, ShmServer& shm_server, DecoyEngine::Settings decoy_settings)
        : m_bouncer(bouncer), m_shm_server(shm_server), m_penalty_engine(bouncer, shm_server),
            m_anomaly_engine(m_penalty_engine, shm_server),
            m_decoy_settings(decoy_settings),
            m_decoy_engine(m_penalty_engine, shm_server, decoy_settings),
            m_http_rate_limiter(bouncer, shm_server),
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

        m_monitored_paths.clear();
        if (rules_json.contains("monitored_paths") && rules_json["monitored_paths"].is_array()) {
            for (const auto& path : rules_json["monitored_paths"]) {
                if (path.is_string()) m_monitored_paths.emplace_back(path.get<std::string>());
            }
        }
        if (m_monitored_paths.empty()) m_monitored_paths.emplace_back("/var/log/");

        for (const auto& rule_data : rules_json["rules"]) {
            Rule rule;
            rule.id = rule_data.value("id", "");
            rule.name = rule_data.value("name", "");
            rule.log_file = rule_data.value("log_file", "");
            rule.category = rule_data.value("category", "");
            if (rule_data.contains("log_files") && rule_data["log_files"].is_array()) {
                for (const auto& path : rule_data["log_files"]) {
                    if (path.is_string()) rule.log_files.push_back(path.get<std::string>());
                }
            }
            if (rule.log_files.empty() && !rule.log_file.empty()) rule.log_files.push_back(rule.log_file);
            std::string raw_pattern = rule_data.value("regex", rule_data.value("pattern", ""));
            rule.max_retry = rule_data.value("max_attempts", rule_data.value("max_retry", 5));
            rule.find_time = rule_data.value("find_time", 60);
            rule.ban_time = rule_data.value("ban_duration", rule_data.value("ban_time", 3600));

            if (rule_data.contains("status_codes") && rule_data["status_codes"].is_array()) {
                for (const auto& sc : rule_data["status_codes"]) {
                    if (sc.is_number_integer()) {
                        rule.status_codes.push_back(sc.get<int>());
                    }
                }
            }

            if (rule.id.empty() || rule.log_files.empty() || raw_pattern.empty()) {
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

            if (rule_data.contains("mitre_tactic")) rule.mitre_tactic = rule_data.value("mitre_tactic", "");
            if (rule_data.contains("mitre_tactic_id")) rule.mitre_tactic_id = rule_data.value("mitre_tactic_id", "");
            if (rule_data.contains("mitre_technique_id")) rule.mitre_technique_id = rule_data.value("mitre_technique_id", "");
            if (rule_data.contains("mitre_technique")) rule.mitre_technique_id = rule_data.value("mitre_technique", "");
            if (rule_data.contains("mitre_technique_name")) rule.mitre_technique_name = rule_data.value("mitre_technique_name", "");

            if (rule_data.contains("mitre")) {
                auto mitre = rule_data["mitre"];
                const auto add_mitre = [&rule](const nlohmann::json& item) {
                    rule.mitre_tactics.push_back(item.value("tactic", ""));
                    rule.mitre_technique_ids.push_back(item.value("technique_id", ""));
                    rule.mitre_technique_names.push_back(item.value("technique_name", ""));
                };
                if (mitre.is_array()) {
                    for (const auto& item : mitre) add_mitre(item);
                    if (!mitre.empty()) {
                        if (rule.mitre_tactic.empty()) rule.mitre_tactic = mitre[0].value("tactic", "");
                        if (rule.mitre_tactic_id.empty()) rule.mitre_tactic_id = mitre[0].value("tactic_id", "");
                        if (rule.mitre_technique_id.empty()) rule.mitre_technique_id = mitre[0].value("technique_id", "");
                        if (rule.mitre_technique_name.empty()) rule.mitre_technique_name = mitre[0].value("technique_name", "");
                        if (rule.mitre_url.empty()) rule.mitre_url = mitre[0].value("url", "");
                    }
                } else {
                    add_mitre(mitre);
                    if (rule.mitre_tactic.empty()) rule.mitre_tactic = mitre.value("tactic", "");
                    if (rule.mitre_tactic_id.empty()) rule.mitre_tactic_id = mitre.value("tactic_id", "");
                    if (rule.mitre_technique_id.empty()) rule.mitre_technique_id = mitre.value("technique_id", "");
                    if (rule.mitre_technique_name.empty()) rule.mitre_technique_name = mitre.value("technique_name", "");
                    if (rule.mitre_url.empty()) rule.mitre_url = mitre.value("url", "");
                }
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
    LogWatcher candidate(m_bouncer, m_shm_server, m_decoy_settings);
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
        for (const auto& path : watch_paths_for_rule(rule)) {
            add_directory_watch(std::filesystem::path(path).parent_path());
            add_file_watch(path);
        }
    }
    for (const auto& path : default_suricata_paths()) {
        add_directory_watch(std::filesystem::path(path).parent_path());
        add_file_watch(path);
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

    std::setlocale(LC_TIME, "C");
    m_next_discovery = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    refresh_dynamic_watches();

    std::lock_guard<std::mutex> lock(m_watch_mutex);
    for (const auto& rule : m_rules) {
        for (const auto& path : watch_paths_for_rule(rule)) {
            if (m_path_to_wd.find(path) != m_path_to_wd.end()) continue;
            add_directory_watch(std::filesystem::path(path).parent_path());
            add_file_watch(path);
        }
    }
    for (const auto& path : default_suricata_paths()) {
        if (m_path_to_wd.find(path) == m_path_to_wd.end()) {
            add_directory_watch(std::filesystem::path(path).parent_path());
            add_file_watch(path);
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
        if (std::chrono::steady_clock::now() >= m_next_discovery) {
            refresh_dynamic_watches();
            m_next_discovery = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        }
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
                        const auto created_path = (dir_it->second / event->name).string();
                        for (const auto& rule : m_rules) {
                            if (rule_matches_file(rule, created_path)) add_file_watch(created_path);
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

void LogWatcher::refresh_dynamic_watches() {
    std::lock_guard<std::mutex> lock(m_watch_mutex);
    std::vector<std::filesystem::path> roots = m_monitored_paths;
    for (const auto& root : roots) {
        std::error_code root_error;
        if (!std::filesystem::is_directory(root, root_error)) continue;
        std::filesystem::recursive_directory_iterator iterator(root,
            std::filesystem::directory_options::skip_permission_denied, root_error);
        const std::filesystem::recursive_directory_iterator end;
        for (; iterator != end; iterator.increment(root_error)) {
            if (root_error) {
                root_error.clear();
                continue;
            }
            std::error_code file_error;
            if (iterator->is_regular_file(file_error) && !file_error && is_dynamic_log_candidate(iterator->path())) {
                add_file_watch(iterator->path().string());
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
    std::error_code canonical_error;
    const auto canonical_path = std::filesystem::weakly_canonical(path, canonical_error);
    const std::string watched_path = canonical_error ? path : canonical_path.string();
    if (m_path_to_wd.find(watched_path) != m_path_to_wd.end() || !std::filesystem::is_regular_file(watched_path)) return;

    const int wd = inotify_add_watch(m_inotify_fd, watched_path.c_str(), IN_MODIFY | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF);
    if (wd < 0) return;

    const int fd = open(watched_path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
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
    state.path = watched_path;
    state.wd = wd;
    state.fd = fd;
    state.read_offset = static_cast<std::uint64_t>(end);
    m_watched_files[wd] = std::move(state);
    m_path_to_wd[watched_path] = wd;
    Logger::get_instance().log(LogLevel::INFO, "SYSTEM", "Monitoring log file: " + watched_path);
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
    if (line.empty()) return;

    // -------------------------------------------------------------
    // 1. PRE-ROUTING WHITELIST (FAST-PATH) SHORT-CIRCUIT EVALUATION
    // Check 127.0.0.0/8, ::1/128, Tailscale 100.64.0.0/10, trusted_cidrs
    // -------------------------------------------------------------
    const std::string pre_routing_ip = fast_extract_ip_from_line(line);
    if (!pre_routing_ip.empty() && is_pre_routing_whitelisted_ip(pre_routing_ip)) {
        // Fast-path: DROP/RETURN immediately without regex, honeypot, or anomaly analysis
        return;
    }

    if (handle_suricata_line(file_path, line)) return;

    // Fast HTTP status code detection (e.g., 200, 400, 403, 404, 500)
    const int http_status_code = fast_extract_http_status_code(line);

    // -------------------------------------------------------------
    // WAF ENHANCEMENT: Multi-Stage String Normalization
    // -------------------------------------------------------------
    const std::string normalized_line = Normalizer::normalize(line);
    const std::string decoded_line = url_decode(normalized_line);

    const bool http_access_log = file_path.find("access.log") != std::string::npos ||
        file_path.find("/nginx/") != std::string::npos ||
        file_path.find("/apache") != std::string::npos;
    if (http_access_log) {
        std::smatch request_match;
        const std::regex request_path_regex(
            R"(\"(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT)\s+([^\s\"]+))",
            std::regex_constants::icase);
        std::smatch source_match;
        const std::regex source_ip_regex(R"((\d{1,3}(?:\.\d{1,3}){3}))");
        const bool has_source_ip = std::regex_search(decoded_line, source_match, source_ip_regex);
        if (has_source_ip && is_pre_routing_whitelisted_ip(source_match[1].str())) {
            return;
        }
        if (has_source_ip && std::regex_search(decoded_line, request_match, request_path_regex) &&
            m_decoy_engine.inspect_request(source_match[1].str(), request_match[1].str())) {
            return;
        }
        if (has_source_ip && m_http_rate_limiter.check_http_rate_limit(source_match[1].str())) {
            Logger::get_instance().log(LogLevel::WARN, "HTTP_FLOOD_BANNED",
                "HTTP request rate exceeded 30 requests per second",
                "CRITICAL", "nftables_drop", source_match[1].str(),
                "http-flood-ddos", "HTTP Flood / Slowloris", 31, 1,
                "Impact", "TA0040", "T1499", "Endpoint Denial of Service", "",
                file_path, line, "threat_prevention", 86400);
            return;
        }
        std::smatch http_ip_match;
        const std::regex http_ip_regex(R"((\d{1,3}(?:\.\d{1,3}){3}))");
        if (std::regex_search(decoded_line, http_ip_match, http_ip_regex)) {
            if (!is_pre_routing_whitelisted_ip(http_ip_match[1].str())) {
                m_anomaly_engine.evaluate_http(http_ip_match[1].str(), decoded_line, decoded_line);
            }
        }
    }

    HoneypotEngine honeypot;
    std::string matched_trap;
    if (honeypot.is_honeypot_hit(decoded_line, matched_trap)) {
        std::string ip = "127.0.0.1";
        std::regex ip_regex(R"((\d{1,3}(?:\.\d{1,3}){3}|[A-Fa-f0-9:]+))");
        std::smatch ip_match;
        if (std::regex_search(normalized_line, ip_match, ip_regex)) {
            ip = ip_match[1].str();
        }

        if (is_pre_routing_whitelisted_ip(ip)) {
            return;
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
            m_penalty_engine.record(ip, 100, "honeypot", line);
        }
        return;
    }

    for (const auto& rule : m_rules) {
        if (!rule_matches_file(rule, file_path)) continue;

        // -------------------------------------------------------------
        // 2. HTTP STATUS CODE FILTER (SKIP REGEX FOR 200 OK IF RESTRICTED)
        // -------------------------------------------------------------
        if (!rule.status_codes.empty() && http_status_code > 0) {
            const bool status_matched = std::any_of(
                rule.status_codes.begin(), rule.status_codes.end(),
                [http_status_code](int sc) { return sc == http_status_code; }
            );
            if (!status_matched) {
                // HTTP Status code not in rule's allowed list (e.g. 200 OK) -> Skip regex evaluation
                continue;
            }
        }

        std::smatch match;
        if (!std::regex_search(decoded_line, match, rule.regex) &&
            !std::regex_search(normalized_line, match, rule.regex)) continue;
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

            if (is_pre_routing_whitelisted_ip(ip)) {
                continue;
            }

            {
                std::lock_guard<std::mutex> correlation_lock(m_suricata_mutex);
                m_suricata_recent["ip:" + ip] = std::chrono::system_clock::now();
            }

            const std::string rule_text = rule.id + " " + rule.name;
            const bool critical = rule_text.find("rce") != std::string::npos ||
                rule_text.find("command") != std::string::npos || rule_text.find("reverse") != std::string::npos;
            const bool high = rule_text.find("sqli") != std::string::npos ||
                rule_text.find("xxe") != std::string::npos || rule_text.find("brute") != std::string::npos ||
                rule_text.find("spray") != std::string::npos;
            const bool medium = rule_text.find("xss") != std::string::npos ||
                rule_text.find("lfi") != std::string::npos || rule_text.find("path") != std::string::npos ||
                rule_text.find("ssrf") != std::string::npos;
            const int threat_points = critical ? 100 : (high ? 60 : (medium ? 35 : 15));
            SiemExporter::instance().export_event("RULE_DETECTION", rule.id, critical ? 10 : high ? 8 : 5,
                ip, "DETECT", line);
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
                    m_penalty_engine.record(ip, threat_points, rule.id, line);
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

bool copsec::LogWatcher::handle_suricata_line(const std::string& file_path, const std::string& line) {
    const bool eve_log = file_path.ends_with("/suricata/eve.json");
    const bool fast_log = file_path.ends_with("/suricata/fast.log");
    if (eve_log) {
        try {
            const auto object = nlohmann::json::parse(line);
            if (object.value("event_type", "") != "alert") return false;
            const auto alert = object.value("alert", nlohmann::json::object());
            const std::uint32_t severity = alert.value("severity", alert.value("priority", 3U));
            record_suricata_alert(object.value("src_ip", ""), alert.value("signature", ""),
                                  alert.value("signature_id", 0U), severity, line);
            return true;
        } catch (const nlohmann::json::exception&) {
            return false;
        }
    }
    if (fast_log) {
        static const std::regex fast_pattern(
            R"(\[\*\*\]\s*\[\d+:(\d+):\d+\]\s*(.*?)\s*\[\*\*\]\s*.*\{.*\}\s*(\d{1,3}(?:\.\d{1,3}){3}))");
        std::smatch match;
        if (!std::regex_search(line, match, fast_pattern)) return true;
        record_suricata_alert(match[3].str(), match[2].str(),
                              static_cast<std::uint32_t>(std::stoul(match[1].str())), 2U, line);
        return true;
    }
    return false;
}

void copsec::LogWatcher::record_suricata_alert(const std::string& ip, const std::string& signature,
                                       std::uint32_t sid, std::uint32_t severity,
                                       const std::string& raw_line) {
    if (ip.empty()) return;
    m_suricata_alerts.fetch_add(1, std::memory_order_relaxed);
    SiemExporter::instance().export_event("SURICATA_ALERT", signature, severity <= 1 ? 10 : severity == 2 ? 7 : 4,
        ip, "DETECT", "mitre=T1190 (Exploit Public-Facing Application) sid=" +
        std::to_string(sid) + " severity=" + std::to_string(severity));
    const int points = severity <= 1 ? copsec::ThreatScoreAccumulator::kHighSeverityPoints :
        (severity == 2 ? copsec::ThreatScoreAccumulator::kLowSeverityPoints : 5);
    const std::string correlation_key = ip + ":" + std::to_string(sid) + ":" + signature;
    const auto now = std::chrono::system_clock::now();
    bool duplicate = false;
    {
        std::lock_guard<std::mutex> lock(m_suricata_mutex);
        const auto found = m_suricata_recent.find(correlation_key);
        const auto ip_found = m_suricata_recent.find("ip:" + ip);
        duplicate = (found != m_suricata_recent.end() &&
            std::chrono::duration_cast<std::chrono::seconds>(now - found->second).count() < 5) ||
            (ip_found != m_suricata_recent.end() &&
            std::chrono::duration_cast<std::chrono::seconds>(now - ip_found->second).count() < 5);
        m_suricata_recent[correlation_key] = now;
        for (auto it = m_suricata_recent.begin(); it != m_suricata_recent.end();) {
            if (std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count() >= 5) it = m_suricata_recent.erase(it);
            else ++it;
        }
    }
    m_shm_server.increment_threats(1);
    copsec::DbManager::get_instance().record_threat_score(ip, points);
    m_shm_server.push_event(ip, "suricata-alert", severity <= 1 ? 86400 : 3600,
                            "Intrusion Detection", "SURICATA:" + std::to_string(sid), signature);
    copsec::DbManager::get_instance().record_incident(ip, "suricata-alert", "Intrusion Detection",
        "SURICATA:" + std::to_string(sid),
        std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count(),
        "", signature, raw_line, duplicate ? "CORRELATED_DUPLICATE" : "SURICATA_ALERT", 0);
    if (!duplicate && severity <= 2) {
        m_penalty_engine.record(ip, points, "suricata-alert", raw_line);
    } else {
        m_penalty_engine.score_only(ip, points);
    }
}

bool copsec::LogWatcher::rule_matches_file(const copsec::Rule& rule, const std::string& file_path) const {
    for (const auto& target : rule.log_files) {
        if (copsec::wildcard_match(target, file_path)) return true;
    }
    if (rule.category == "web" || rule.category == "sqli" || rule.category == "xss" ||
        rule.category == "rce" || rule.category == "lfi" || rule.category == "ssrf") {
        return copsec::is_web_log_path(file_path);
    }
    return false;
}

bool copsec::LogWatcher::check_rate_limit(const std::string& rule_id, const std::string& ip, int max_retry, int find_time, int& current_count) {
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
