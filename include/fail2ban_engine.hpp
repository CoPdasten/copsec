#pragma once

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

namespace copsec {

class Fail2banEngine {
public:
    struct BanStatus {
        std::string ip;
        int multiplier = 1;
        int current_ban_seconds = 0;
    };

    explicit Fail2banEngine(std::string state_path = "/var/run/copsec/fail2ban_state.json")
        : m_state_path(std::move(state_path)) {
        std::error_code ec;
        std::filesystem::create_directories("/var/run/copsec", ec);
        load_state();
    }

    int evaluate_ip(const std::string& ip, int base_ban_time, int find_time_seconds, int max_multiplier = 32) {
        if (ip.empty()) {
            return base_ban_time;
        }

        std::lock_guard<std::mutex> lock(m_mutex);
        auto now = std::chrono::system_clock::now();
        auto& history = m_ip_history[ip];

        auto cutoff = now - std::chrono::seconds(find_time_seconds);
        history.erase(
            std::remove_if(history.begin(), history.end(), [cutoff](const std::chrono::system_clock::time_point& ts) {
                return ts < cutoff;
            }),
            history.end());

        history.push_back(now);

        int multiplier = 1;
        int repeats = count_recent_bans(ip, std::chrono::hours(24));
        while (repeats > 0 && multiplier < max_multiplier) {
            multiplier *= 2;
            --repeats;
        }

        const int escalated = std::min(base_ban_time * multiplier, 7 * 24 * 60 * 60);
        m_ip_status[ip].ip = ip;
        m_ip_status[ip].multiplier = multiplier;
        m_ip_status[ip].current_ban_seconds = escalated;

        save_state();
        return escalated;
    }

    std::string auto_aggregate_subnet_if_needed(const std::string& ip, int window_seconds = 600, int threshold = 3) {
        if (ip.empty()) {
            return "";
        }

        std::lock_guard<std::mutex> lock(m_mutex);
        const std::string subnet = to_subnet24(ip);
        if (subnet.empty()) {
            return "";
        }

        auto now = std::chrono::system_clock::now();
        auto& hits = m_subnet_hits[subnet];
        auto cutoff = now - std::chrono::seconds(window_seconds);
        hits.erase(
            std::remove_if(hits.begin(), hits.end(), [cutoff](const std::chrono::system_clock::time_point& ts) {
                return ts < cutoff;
            }),
            hits.end());

        hits.push_back(now);

        auto distinct = distinct_ips_in_subnet(subnet, window_seconds);
        if (static_cast<int>(distinct.size()) >= threshold) {
            m_auto_banned_subnets.insert(subnet);
            save_state();
            return subnet;
        }
        return "";
    }

    std::vector<BanStatus> active_status() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<BanStatus> status;
        for (const auto& [ip, state] : m_ip_status) {
            status.push_back(state);
        }
        return status;
    }

    std::vector<std::string> auto_banned_subnets() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<std::string> subnets(m_auto_banned_subnets.begin(), m_auto_banned_subnets.end());
        return subnets;
    }

    std::string status_report() const {
        std::ostringstream out;
        out << "=== Fail2ban Status ===\n";

        const auto status = active_status();
        if (status.empty()) {
            out << "No active sliding-window entries.\n";
        } else {
            for (const auto& item : status) {
                out << "IP: " << item.ip << " | multiplier: x" << item.multiplier
                    << " | current_ban: " << item.current_ban_seconds << "s\n";
            }
        }

        const auto blocked = auto_banned_subnets();
        if (blocked.empty()) {
            out << "Auto-banned /24 subnets: none\n";
        } else {
            out << "Auto-banned /24 subnets:\n";
            for (const auto& subnet : blocked) {
                out << "  - " << subnet << "\n";
            }
        }

        return out.str();
    }

    std::string to_subnet24(const std::string& ip) const {
        std::string normalized = ip;
        if (normalized.find('/') != std::string::npos) {
            return normalized;
        }

        if (normalized.find(':') != std::string::npos) {
            return "";
        }

        std::vector<int> octets;
        std::stringstream ss(normalized);
        std::string token;
        while (std::getline(ss, token, '.')) {
            if (token.empty()) {
                return "";
            }
            try {
                const int value = std::stoi(token);
                if (value < 0 || value > 255) {
                    return "";
                }
                octets.push_back(value);
            } catch (...) {
                return "";
            }
        }

        if (octets.size() != 4) {
            return "";
        }

        std::ostringstream subnet;
        subnet << octets[0] << '.' << octets[1] << '.' << octets[2] << ".0/24";
        return subnet.str();
    }

private:
    int count_recent_bans(const std::string& ip, const std::chrono::hours& window) const {
        auto now = std::chrono::system_clock::now();
        auto cutoff = now - window;
        int count = 0;
        auto it = m_ip_history.find(ip);
        if (it == m_ip_history.end()) {
            return 0;
        }
        for (const auto& ts : it->second) {
            if (ts >= cutoff) {
                ++count;
            }
        }
        return count;
    }

    std::set<std::string> distinct_ips_in_subnet(const std::string& subnet, int window_seconds) const {
        std::set<std::string> result;
        auto now = std::chrono::system_clock::now();
        auto cutoff = now - std::chrono::seconds(window_seconds);
        for (const auto& [ip, history] : m_ip_history) {
            if (to_subnet24(ip) == subnet) {
                for (const auto& ts : history) {
                    if (ts >= cutoff) {
                        result.insert(ip);
                        break;
                    }
                }
            }
        }
        return result;
    }

    void load_state() {
        std::ifstream input(m_state_path);
        if (!input.is_open()) {
            return;
        }

        try {
            nlohmann::json j;
            input >> j;
            if (j.contains("ip_status") && j["ip_status"].is_object()) {
                for (auto it = j["ip_status"].begin(); it != j["ip_status"].end(); ++it) {
                    const std::string ip = it.key();
                    BanStatus status;
                    status.ip = ip;
                    status.multiplier = it.value().value("multiplier", 1);
                    status.current_ban_seconds = it.value().value("current_ban_seconds", 0);
                    m_ip_status[ip] = status;
                }
            }
            if (j.contains("subnets") && j["subnets"].is_array()) {
                for (const auto& subnet : j["subnets"]) {
                    m_auto_banned_subnets.insert(subnet.get<std::string>());
                }
            }
        } catch (...) {
        }
    }

    void save_state() const {
        std::ofstream output(m_state_path, std::ios::trunc);
        if (!output.is_open()) {
            return;
        }

        nlohmann::json j;
        nlohmann::json ip_status = nlohmann::json::object();
        for (const auto& [ip, status] : m_ip_status) {
            ip_status[ip] = {
                {"multiplier", status.multiplier},
                {"current_ban_seconds", status.current_ban_seconds}
            };
        }
        j["ip_status"] = ip_status;
        std::vector<std::string> subnets(m_auto_banned_subnets.begin(), m_auto_banned_subnets.end());
        j["subnets"] = subnets;
        output << j.dump(2);
    }

    mutable std::mutex m_mutex;
    std::string m_state_path;
    std::unordered_map<std::string, std::vector<std::chrono::system_clock::time_point>> m_ip_history;
    std::unordered_map<std::string, BanStatus> m_ip_status;
    std::unordered_map<std::string, std::vector<std::chrono::system_clock::time_point>> m_subnet_hits;
    std::set<std::string> m_auto_banned_subnets;
};

} // namespace copsec
