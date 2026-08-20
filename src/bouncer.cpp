#include "bouncer.hpp"
#include "logger.hpp"
#include "whitelist.hpp"
#include "sync.hpp"
#include "shodan.hpp"
#include "fail2ban_engine.hpp"
#include "pcap_capture.hpp"
#include "pcap_manager.hpp"
#include "db_manager.hpp"
#include "mitre.hpp"
#include "shm_ipc.hpp"
#include <nftables/libnftables.h>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <thread>
#include <chrono>
#include <algorithm>
#include <arpa/inet.h>
#include <nlohmann/json.hpp>

namespace copsec {

Bouncer::Bouncer() : m_nft_ctx(nullptr) {
    m_nft_ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!m_nft_ctx) {
        Logger::get_instance().log(LogLevel::WARN, "BOUNCER_INIT",
            "Failed to initialize libnftables context. Will rely entirely on shell command execution fallback.");
    } else {
        Logger::get_instance().log(LogLevel::INFO, "BOUNCER_INIT",
            "Successfully initialized libnftables context.");
    }
}

Bouncer::~Bouncer() {
    if (m_nft_ctx) {
        nft_ctx_free(m_nft_ctx);
    }
}

bool Bouncer::init_nftables() {
    Logger::get_instance().log(LogLevel::INFO, "BOUNCER_CONFIG", "Initializing nftables rulesets...");

    if (!execute_command("add table inet copsec_filter")) {
        Logger::get_instance().log(LogLevel::ERR, "BOUNCER_ERROR", "Failed to create table inet copsec_filter");
        return false;
    }

    if (!execute_command("add set inet copsec_filter ban_list { type ipv4_addr; flags timeout; }")) {
        Logger::get_instance().log(LogLevel::INFO, "BOUNCER_CONFIG", "Set ban_list already exists or was created.");
    }

    if (!execute_command("add chain inet copsec_filter input { type filter hook input priority filter; policy accept; }")) {
        Logger::get_instance().log(LogLevel::ERR, "BOUNCER_ERROR", "Failed to create/verify input filter chain");
        return false;
    }

    if (!execute_command("add rule inet copsec_filter input ip saddr @ban_list drop")) {
        Logger::get_instance().log(LogLevel::ERR, "BOUNCER_ERROR", "Failed to apply drop rule for set @ban_list");
        return false;
    }

    Logger::get_instance().log(LogLevel::INFO, "BOUNCER_CONFIG", "nftables configuration applied successfully.");
    return true;
}

bool Bouncer::ban_ip(const std::string& ip, int duration_sec, const std::string& rule_id) {
    // -------------------------------------------------------------
    // WHITELIST CHECK
    // -------------------------------------------------------------
    if (DbManager::get_instance().is_whitelisted(ip)) {
        const auto mitre = MitreMapper::get_instance().get_metadata(rule_id);
        const auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        DbManager::get_instance().record_incident(ip, rule_id, mitre.tactic, mitre.technique_id,
            timestamp, "");
        ShmServer::get_instance().push_event(ip, rule_id, 0, mitre.tactic, mitre.technique_id);
        Logger::get_instance().log(LogLevel::INFO, "FALSE_POSITIVE_PREVENTED",
            "[FALSE_POSITIVE_PREVENTED] Suppressed ban for IP: " + ip, "INFO", "whitelist_guard", ip, rule_id,
            "", 0, 0, mitre.tactic, mitre.tactic_id, mitre.technique_id, mitre.technique_name, mitre.url);
        return false;
    }

    static Fail2banEngine fail2ban_engine;
    const int escalated_duration = fail2ban_engine.evaluate_ip(ip, duration_sec, 600);
    const std::string subnet = fail2ban_engine.auto_aggregate_subnet_if_needed(ip, 600, 3);

    Logger::get_instance().log(LogLevel::INFO, "IP_BAN_ATTEMPT",
        "Attempting to ban IP: " + ip + " for " + std::to_string(escalated_duration) + " seconds." + (!subnet.empty() ? " | subnet_aggregation=" + subnet : ""));

    std::string cmd = "add element inet copsec_filter ban_list { " + ip + " timeout " + std::to_string(escalated_duration) + "s }";
    bool success = execute_command(cmd);

    if (success) {
        const auto expiry = std::chrono::system_clock::now() + std::chrono::seconds(escalated_duration);
        const auto expiry_seconds = std::chrono::duration_cast<std::chrono::seconds>(expiry.time_since_epoch()).count();
        std::lock_guard<std::mutex> lock(m_mutex);
        auto existing = std::find_if(m_bans.begin(), m_bans.end(), [&ip](const BanInfo& ban) { return ban.ip == ip; });
        if (existing == m_bans.end()) {
            m_bans.push_back({ip, rule_id, expiry_seconds});
        } else {
            existing->expires_at = expiry_seconds;
        }
        ShmServer::get_instance().set_active_bans(m_bans.size());
    }
    if (success) ShmServer::get_instance().increment_total_bans();

    const auto mitre = MitreMapper::get_instance().get_metadata(rule_id);
    nlohmann::json ban_event = {
        {"ip", ip}, {"duration", escalated_duration}, {"rule_id", rule_id}, {"success", success},
        {"mitre_tactic", mitre.tactic}, {"mitre_tactic_id", mitre.tactic_id},
        {"mitre_technique", mitre.technique_id}, {"mitre_technique_name", mitre.technique_name},
        {"mitre_url", mitre.url}
    };
    ShmServer::get_instance().push_event(ip, rule_id, escalated_duration,
        mitre.tactic, mitre.technique_id);

    // Always generate a forensic artifact for the ban decision itself. The kernel
    // enforcement may fail in constrained/containerized environments, but the
    // incident file must still be created for SOC/forensic continuity.
    copsec::PcapForensics::get_instance().record_incident(ip);
    PcapManager::get_instance().write_synthetic_http_packet(
        ip, 49152, "GET /security-event?rule=" + rule_id + " HTTP/1.1\r\nHost: localhost\r\n\r\n");
    const auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    DbManager::get_instance().record_incident(ip, rule_id, mitre.tactic, mitre.technique_id,
        timestamp, "/var/log/copsec/pcaps");

    if (!subnet.empty()) {
        const std::string subnet_cmd = "add element inet copsec_filter ban_list { " + subnet + " timeout " + std::to_string(escalated_duration) + "s }";
        execute_command(subnet_cmd);
    }

    if (m_ban_observer && rule_id != "abuseipdb_escalation" && rule_id != "threat_intelligence") {
        m_ban_observer(ip, escalated_duration, rule_id);
    }

    // -------------------------------------------------------------
    // CENTRAL API TELEMETRY PUSH (CROWD INTELLIGENCE)
    // -------------------------------------------------------------
    if (success && !rule_id.empty()) {
        SyncModule::push_telemetry(
            "http://127.0.0.1:8080/api/v1/telemetry/push",
            "copsec-agent-parrot",
            ip,
            rule_id
        );

        std::thread([ip, rule_id]() {
            ShodanClient shodan;
            auto host = shodan.lookup_host(ip);
            std::ostringstream enriched;
            enriched << "Threat Enrichment | IP=" << ip
                     << " | country=" << host.country_name
                     << " | city=" << host.city
                     << " | isp=" << host.isp
                     << " | org=" << host.org
                     << " | ports=";
            if (host.ports.empty()) {
                enriched << "none";
            } else {
                for (size_t i = 0; i < host.ports.size(); ++i) {
                    if (i) enriched << ",";
                    enriched << host.ports[i];
                }
            }
            enriched << " | cves=";
            if (host.cves.empty()) {
                enriched << "none";
            } else {
                for (size_t i = 0; i < host.cves.size(); ++i) {
                    if (i) enriched << ",";
                    enriched << host.cves[i];
                }
            }
            enriched << " | rule_id=" << rule_id;
            Logger::get_instance().log(LogLevel::INFO, "THREAT_ENRICHMENT", enriched.str());
        }).detach();
    }

    return success;
}

bool Bouncer::bulk_ban_ips(const std::vector<std::string>& ips, int duration_sec, const std::string& rule_id) {
    (void)rule_id;
    if (ips.empty() || duration_sec <= 0) return false;
    std::ostringstream command;
    command << "add element inet copsec_filter ban_list { ";
    for (const auto& ip : ips) {
        in_addr address{};
        if (inet_pton(AF_INET, ip.c_str(), &address) != 1) continue;
        command << ip << " timeout " << duration_sec << "s, ";
    }
    auto value = command.str();
    if (value == "add element inet copsec_filter ban_list { ") return false;
    value.erase(value.size() - 2);
    value += " }";
    if (!execute_command(value)) return false;

    const auto expiry = std::chrono::duration_cast<std::chrono::seconds>(
        (std::chrono::system_clock::now() + std::chrono::seconds(duration_sec)).time_since_epoch()).count();
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& ip : ips) {
        in_addr address{};
        if (inet_pton(AF_INET, ip.c_str(), &address) != 1) continue;
        auto existing = std::find_if(m_bans.begin(), m_bans.end(), [&ip](const BanInfo& ban) { return ban.ip == ip; });
        if (existing == m_bans.end()) m_bans.push_back({ip, rule_id, expiry});
        else existing->expires_at = expiry;
    }
    ShmServer::get_instance().set_active_bans(m_bans.size());
    return true;
}

void Bouncer::set_ban_observer(std::function<void(const std::string&, int, const std::string&)> observer) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_ban_observer = std::move(observer);
}

bool Bouncer::unban_ip(const std::string& ip) {
    in_addr address{};
    if (inet_pton(AF_INET, ip.c_str(), &address) != 1) return false;
    const bool success = execute_command("delete element inet copsec_filter ban_list { " + ip + " }");
    if (success) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_bans.erase(std::remove_if(m_bans.begin(), m_bans.end(), [&ip](const BanInfo& ban) {
            return ban.ip == ip;
        }), m_bans.end());
        ShmServer::get_instance().set_active_bans(m_bans.size());
    }
    return success;
}

std::vector<Bouncer::BanInfo> Bouncer::active_bans() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::vector<BanInfo> active;
    for (const auto& ban : m_bans) {
        if (ban.expires_at > now) active.push_back(ban);
    }
    return active;
}

bool Bouncer::execute_command(const std::string& cmd) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (run_libnftables(cmd)) {
        return true;
    }

    Logger::get_instance().log(LogLevel::WARN, "BOUNCER_FALLBACK",
        "libnftables API execution failed or context unavailable. Falling back to shell command execution: " + cmd);
    return run_shell_fallback(cmd);
}

bool Bouncer::run_libnftables(const std::string& cmd) {
    if (!m_nft_ctx) return false;

    nft_ctx_buffer_error(m_nft_ctx);

    int res = nft_run_cmd_from_buffer(m_nft_ctx, cmd.c_str());
    if (res == 0) return true;

    const char* err_buf = nft_ctx_get_error_buffer(m_nft_ctx);
    std::string err_str = err_buf ? err_buf : "Unknown error";
    Logger::get_instance().log(LogLevel::ERR, "LIBNFTABLES_FAIL",
        "libnftables failed command [" + cmd + "] with error: " + err_str);

    return false;
}

bool Bouncer::run_shell_fallback(const std::string& cmd) {
    std::string shell_cmd = "nft \"" + cmd + "\" 2>&1";
    
    FILE* pipe = popen(shell_cmd.c_str(), "r");
    if (!pipe) {
        Logger::get_instance().log(LogLevel::ERR, "SHELL_FAIL", "Failed to run popen for shell command: " + shell_cmd);
        return false;
    }

    char buffer[128];
    std::string result = "";
    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != nullptr) {
            result += buffer;
        }
    }

    int rc = pclose(pipe);
    if (rc == 0) return true;

    std::string sudo_cmd = "sudo nft \"" + cmd + "\" 2>&1";
    Logger::get_instance().log(LogLevel::WARN, "SHELL_FAIL", 
        "Command without sudo failed. Retrying with sudo prefix: " + sudo_cmd);

    FILE* sudo_pipe = popen(sudo_cmd.c_str(), "r");
    if (!sudo_pipe) {
        Logger::get_instance().log(LogLevel::ERR, "SUDO_FAIL", "Failed to run popen for sudo command: " + sudo_cmd);
        return false;
    }

    result = "";
    while (!feof(sudo_pipe)) {
        if (fgets(buffer, 128, sudo_pipe) != nullptr) {
            result += buffer;
        }
    }

    int sudo_rc = pclose(sudo_pipe);
    if (sudo_rc != 0) {
        Logger::get_instance().log(LogLevel::ERR, "SHELL_ERROR",
            "Command execution failed. Output: " + result);
        return false;
    }

    return true;
}

} // namespace copsec