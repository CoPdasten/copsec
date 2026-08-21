#include <cstdlib>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>
#include <regex>
#include <thread>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <unistd.h>

#include "fail2ban_engine.hpp"
#include "db_manager.hpp"
#include "mitre_fetcher.hpp"
#include "mitre_engine.hpp"
#include "mitre.hpp"
#include "pcap_capture.hpp"
#include "pcap_manager.hpp"
#include "shm_ipc.hpp"
#include "shodan.hpp"
#include "stix_parser.hpp"
#include "suricata_parser.hpp"
#include "xdp_bouncer.hpp"

namespace {

std::string exec_cmd(const std::string& command) {
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        return "";
    }

    char buffer[512];
    std::string result;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    pclose(pipe);
    return result;
}

bool run_nft_command(const std::string& command, std::string& output, bool use_sudo = true) {
    std::string cmd = "nft " + command + " 2>&1";
    output = exec_cmd(cmd);
    if (output.find("Error") == std::string::npos && output.find("failed") == std::string::npos && output.find("not found") == std::string::npos) {
        return true;
    }

    if (use_sudo) {
        cmd = "sudo nft " + command + " 2>&1";
        output = exec_cmd(cmd);
        if (output.find("Error") == std::string::npos && output.find("failed") == std::string::npos && output.find("not found") == std::string::npos) {
            return true;
        }
    }

    return false;
}

std::size_t count_ipv4_entries(const std::string& output) {
    const std::regex address(R"(\b(?:\d{1,3}\.){3}\d{1,3}\b)");
    return static_cast<std::size_t>(std::distance(
        std::sregex_iterator(output.begin(), output.end(), address), std::sregex_iterator()));
}

std::size_t count_suricata_alerts(const std::filesystem::path& path, bool eve_json) {
    std::ifstream input(path);
    if (!input.is_open()) return 0;
    std::size_t count = 0;
    std::string line;
    while (std::getline(input, line)) {
        if (eve_json) {
            try {
                if (nlohmann::json::parse(line).value("event_type", "") == "alert") ++count;
            } catch (const nlohmann::json::exception&) {
            }
        } else if (line.find("[**]") != std::string::npos) {
            ++count;
        }
    }
    return count;
}

std::string fit_cell(const std::string& value, std::size_t width) {
    if (value.size() <= width) return value + std::string(width - value.size(), ' ');
    return value.substr(0, width - 3) + "...";
}

void print_ban_table(const std::string& nft_output) {
    struct BanRow { std::string ip, duration, reason, mitre; };
    std::vector<BanRow> rows;
    const std::regex address(R"(\b(?:\d{1,3}\.){3}\d{1,3}\b)");
    for (std::sregex_iterator iterator(nft_output.begin(), nft_output.end(), address), end; iterator != end; ++iterator) {
        const std::string ip = iterator->str();
        std::string duration = "active";
        const auto line_start = nft_output.rfind('\n', iterator->position());
        const auto line_end = nft_output.find('\n', iterator->position());
        const std::string line = nft_output.substr(line_start == std::string::npos ? 0 : line_start + 1,
            line_end == std::string::npos ? std::string::npos : line_end - line_start - 1);
        const auto timeout = line.find("timeout ");
        if (timeout != std::string::npos) duration = line.substr(timeout + 8);
        std::string reason = "nftables ban";
        std::string mitre = "Unknown";
        if (copsec::DbManager::get_instance().initialized()) {
            for (const auto& incident : copsec::DbManager::get_instance().recent_incidents(500)) {
                if (incident.src_ip == ip) {
                    reason = incident.rule_id.empty() ? reason : incident.rule_id;
                    mitre = incident.mitre_technique_id.empty() ? mitre :
                        incident.mitre_technique_id + " (" + incident.mitre_technique_name + ")";
                    break;
                }
            }
        }
        rows.push_back({ip, duration, reason, mitre});
    }
    constexpr std::size_t ip_width = 15, duration_width = 11, reason_width = 30, mitre_width = 25;
    const std::string top = "┌─────────────────┬─────────────┬────────────────────────────────┬───────────────────────────┐\n";
    const std::string middle = "├─────────────────┼─────────────┼────────────────────────────────┼───────────────────────────┤\n";
    const std::string bottom = "└─────────────────┴─────────────┴────────────────────────────────┴───────────────────────────┘\n";
    std::cout << '\n' << top << "│ " << fit_cell("IP ADDRESS", ip_width) << " │ " << fit_cell("DURATION", duration_width)
              << " │ " << fit_cell("REASON / TECHNIQUE", reason_width) << " │ " << fit_cell("MITRE ATT&CK", mitre_width) << " │\n" << middle;
    for (const auto& row : rows) {
        std::cout << "│ " << fit_cell(row.ip, ip_width) << " │ " << fit_cell(row.duration, duration_width)
                  << " │ " << fit_cell(row.reason, reason_width) << " │ " << fit_cell(row.mitre, mitre_width) << " │\n";
    }
    std::cout << bottom;
}

std::string tail_file(const std::filesystem::path& path, std::size_t max_lines = 8) {
    std::ifstream input(path);
    if (!input.is_open()) return "(not available)";
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(input, line)) {
        lines.push_back(std::move(line));
        if (lines.size() > max_lines) lines.erase(lines.begin());
    }
    std::ostringstream output;
    for (const auto& entry : lines) output << entry << '\n';
    return output.str().empty() ? "(no events)\n" : output.str();
}

pid_t find_daemon_pid() {
    std::ifstream pid_file("/var/run/copsec.pid");
    pid_t pid = 0;
    if (pid_file >> pid && pid > 1 && kill(pid, 0) == 0) return pid;

    try {
        for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
            if (!entry.is_directory()) continue;
            const std::string name = entry.path().filename().string();
            if (name.empty() || name.find_first_not_of("0123456789") != std::string::npos) continue;

            std::ifstream command_line(entry.path() / "cmdline");
            std::string command;
            std::getline(command_line, command, '\0');
            if (command.empty() || command == "copsec-cli" || command.find("/copsec-cli") != std::string::npos) continue;
            if (command == "copsec" || command.find("/copsec") != std::string::npos) {
                return static_cast<pid_t>(std::stol(name));
            }
        }
    } catch (const std::exception&) {
        return 0;
    }
    return 0;
}

void print_usage() {
        std::cout << R"CLI(CoPSeC Enterprise Agent CLI

Management:
    status                         Show nftables enforcement status
    start | stop | restart         Control the copsec system service
    version                        Show CLI version
    update                         Pull, build, install, and restart the agent

Whitelist:
    whitelist add <ip> "<reason>" Add a trusted IP or CIDR
    whitelist remove <ip>          Remove a trusted IP or CIDR
    whitelist list                 List trusted networks

Bans / Threat Mitigation:
    ban list                        List all actively banned IP addresses
    ban add <ip> "<reason>"          Manually ban an IP address
    ban remove <ip>                 Unban a specific IP address
    ban clear-list                  Flush active nftables ban set (preserves internal history/scores)

Inspection:
    lookup <ip>                     Query host intelligence
    shm                             Show shared-memory telemetry

Storage & Maintenance:
    purge-pcaps                     Delete captured .pcap/.pcapng files
    db-vacuum                       Reclaim SQLite database storage
    pcap list                       List forensic captures

Detection & Intelligence:
    scores                         List active adaptive threat scores
    fail2ban status                 Show escalation state
    suricata status                 Show Suricata watcher state
    xdp status                      Show XDP status
    monitor                        Live threat and security event monitor
    mitre <technique> [--offline]   Query MITRE ATT&CK
    mitre <technique> --taxii <url> Refresh and query a TAXII STIX bundle

Configuration:
    config-reload                   Request a configuration reload
    help | --help                   Show this help screen
)CLI";
}

void print_host_info(const copsec::ShodanHostInfo& info) {
    std::cout << "=== Shodan Host Intelligence ===\n";
    std::cout << "Country: " << info.country_name << "\n";
    std::cout << "City:    " << info.city << "\n";
    std::cout << "ISP:     " << info.isp << "\n";
    std::cout << "Org:     " << info.org << "\n";
    std::cout << "Ports:   ";
    if (info.ports.empty()) {
        std::cout << "none\n";
    } else {
        for (size_t i = 0; i < info.ports.size(); ++i) {
            if (i) std::cout << ", ";
            std::cout << info.ports[i];
        }
        std::cout << "\n";
    }
    std::cout << "CVEs:    ";
    if (info.cves.empty()) {
        std::cout << "none\n";
    } else {
        for (size_t i = 0; i < info.cves.size(); ++i) {
            if (i) std::cout << ", ";
            std::cout << info.cves[i];
        }
        std::cout << "\n";
    }
}

void print_mitre_info(const copsec::MitreTechniqueInfo& info) {
    std::cout << "=== MITRE ATT&CK Technique ===\n";
    std::cout << "ID:          " << info.id << "\n";
    std::cout << "Name:        " << (info.name.empty() ? "unknown" : info.name) << "\n";
    std::cout << "Description: " << (info.description.empty() ? "No description available." : info.description) << "\n";
    std::cout << "Tactics:     ";
    if (info.tactics.empty()) {
        std::cout << "unknown\n";
    } else {
        for (size_t i = 0; i < info.tactics.size(); ++i) {
            if (i) std::cout << ", ";
            std::cout << info.tactics[i];
        }
        std::cout << "\n";
    }
    std::cout << "Sub-techniques: ";
    if (info.sub_techniques.empty()) {
        std::cout << "none\n";
    } else {
        for (size_t i = 0; i < info.sub_techniques.size(); ++i) {
            if (i) std::cout << ", ";
            std::cout << info.sub_techniques[i];
        }
        std::cout << "\n";
    }
    std::cout << "Platforms:   ";
    if (info.platforms.empty()) {
        std::cout << "unknown\n";
    } else {
        for (size_t i = 0; i < info.platforms.size(); ++i) {
            if (i) std::cout << ", ";
            std::cout << info.platforms[i];
        }
        std::cout << "\n";
    }
    std::cout << "Mitigations:\n";
    if (info.mitigations.empty()) {
        std::cout << "  none\n";
    } else {
        for (const auto& mitigation : info.mitigations) {
            std::cout << "  - " << mitigation << "\n";
        }
    }
}

void print_stix_profile(const copsec::TechniqueProfile& profile, const std::vector<copsec::ThreatActorProfile>& actors) {
    std::cout << "=== Offline STIX 2.1 Technique ===\n";
    std::cout << "ID:          " << profile.id << "\n";
    std::cout << "Name:        " << (profile.name.empty() ? "unknown" : profile.name) << "\n";
    std::cout << "Description: " << (profile.description.empty() ? "No description available." : profile.description) << "\n";
    std::cout << "Tactics:     ";
    if (profile.tactics.empty()) {
        std::cout << "unknown\n";
    } else {
        for (size_t i = 0; i < profile.tactics.size(); ++i) {
            if (i) std::cout << ", ";
            std::cout << profile.tactics[i];
        }
        std::cout << "\n";
    }
    std::cout << "Mitigations:\n";
    if (profile.mitigations.empty()) {
        std::cout << "  none\n";
    } else {
        for (const auto& mitigation : profile.mitigations) {
            std::cout << "  - " << mitigation << "\n";
        }
    }
    std::cout << "Actors:\n";
    if (actors.empty()) {
        std::cout << "  none\n";
    } else {
        for (const auto& actor : actors) {
            std::cout << "  - " << actor.name << "\n";
            if (!actor.description.empty()) {
                std::cout << "      " << actor.description << "\n";
            }
        }
    }
}

void print_mitre_rule_context(const std::string& technique_id) {
    std::vector<std::string> candidates = {"config/rules.json", "../config/rules.json", "/etc/copsec/rules.json"};
    nlohmann::json root;
    for (const auto& candidate : candidates) {
        std::ifstream input(candidate);
        if (input.is_open()) {
            try { input >> root; } catch (...) { root = {}; }
            if (!root.empty()) break;
        }
    }

    std::cout << "Rules:       ";
    bool found_rule = false;
    if (root.contains("rules") && root["rules"].is_array()) {
        for (const auto& rule : root["rules"]) {
            const auto mapping = rule.value("mitre", nlohmann::json::object());
            bool matches = false;
            if (mapping.is_array()) {
                for (const auto& item : mapping) matches = matches || item.value("technique_id", "") == technique_id;
            } else {
                matches = mapping.value("technique_id", "") == technique_id;
            }
            if (matches) {
                if (found_rule) std::cout << ", ";
                std::cout << rule.value("id", rule.value("name", "unknown"));
                found_rule = true;
            }
        }
    }
    if (!found_rule) std::cout << "none";
    std::cout << "\nTriggers (24h): ";
    std::size_t recent = 0;
    const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    auto& database = copsec::DbManager::get_instance();
    if (database.initialize()) {
        for (const auto& incident : database.recent_incidents(10000)) {
            if (incident.mitre_technique_id != technique_id) continue;
            try {
                if (now_ms - std::stoll(incident.timestamp) <= 86400000) ++recent;
            } catch (...) {
            }
        }
    }
    std::cout << recent << "\n";
}

void print_shm_snapshot(const copsec::ShmSnapshot& snapshot) {
    std::cout << "=== CoPSeC Shared Memory IPC ===\n";
    std::cout << "Active bans:           " << snapshot.active_bans << "\n";
    std::cout << "Total processed lines:  " << snapshot.total_processed_lines << "\n";
    std::cout << "Threat detections:      " << snapshot.total_threats << "\n";
    std::cout << "Total bans:            " << snapshot.total_bans << "\n";
    std::cout << "Loaded rules:           " << snapshot.rule_count << "\n";
    std::cout << "Memory footprint:      " << snapshot.memory_size << " bytes\n";
    std::cout << "Ring buffer entries:   " << snapshot.ring_count << "/50\n";
    if (!snapshot.events.empty()) {
        const auto& event = snapshot.events.back();
        std::cout << "Recent event:          rule=" << event.rule_id
                  << " ip=" << event.ip
                  << " technique=" << event.mitre_technique << "\n";
    }
    std::cout << "Recent events:\n";
    if (snapshot.events.empty()) {
        std::cout << "  none\n";
        return;
    }

    for (const auto& event : snapshot.events) {
        std::cout << "  - IP=" << event.ip
                  << " | rule=" << event.rule_id
                  << " | mitre_tactic=" << event.mitre_tactic
                  << " | mitre_technique=" << event.mitre_technique
                  << " - " << event.mitre_technique_name
                  << " | ban=" << event.ban_duration
                  << "s | ts=" << event.timestamp_ms << "\n";
    }
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2 || std::string(argv[1]) == "help" || std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h") {
        print_usage();
        return argc < 2 ? 1 : 0;
    }

    std::string command = argv[1];

    if (command == "version") {
        std::cout << "CoPSeC Enterprise Agent CLI 1.0.0\n";
        return 0;
    }

    if (command == "scores") {
        auto& database = copsec::DbManager::get_instance();
        if (!database.initialize()) {
            std::cerr << "Unable to open score database.\n";
            return 1;
        }
        const auto now = std::chrono::system_clock::now();
        std::cout << "IP\tSCORE\tRISK\tTIME_TO_DECAY\n";
        for (const auto& entry : database.list_threat_scores()) {
            const auto updated = std::chrono::system_clock::time_point(std::chrono::seconds(entry.updated_at));
            const auto elapsed_seconds = std::max<int64_t>(0, std::chrono::duration_cast<std::chrono::seconds>(now - updated).count());
            const int effective_score = std::min(100, std::max(0, entry.points - static_cast<int>(elapsed_seconds / 3600) * 10));
            if (effective_score == 0) continue;
            const char* risk = effective_score >= 100 ? "CRITICAL" : effective_score >= 60 ? "HIGH" : effective_score >= 30 ? "SUSPICIOUS" : "LOW";
            const auto remaining_minutes = 60 - ((elapsed_seconds % 3600) / 60);
            std::cout << entry.ip << '\t' << effective_score << '\t' << risk << '\t'
                      << remaining_minutes << "m\n";
        }
        return 0;
    }

    if (command == "monitor") {
        auto& database = copsec::DbManager::get_instance();
        database.initialize();
        while (true) {
            std::cout << "\033[2J\033[H";
            std::string nft_output;
            const bool nft_ok = run_nft_command("list set inet copsec_filter ban_list", nft_output);
            const bool eve_active = std::filesystem::is_regular_file("/var/log/suricata/eve.json");
            std::cout << "CoPSeC LIVE MONITOR  " << std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()) << "\n\n";
            std::cout << "SYSTEM & ENFORCEMENT STATUS\n"
                      << "  nftables: " << (nft_ok ? "active" : "unavailable")
                      << " | active bans: " << (nft_ok ? count_ipv4_entries(nft_output) : 0) << "\n";
            auto& xdp = copsec::XdpBouncer::get_instance();
            xdp.refresh_kernel_stats();
            std::cout << "  eBPF/XDP: " << (xdp.get_stats().packets_processed > 0 ? "active" : "inactive")
                      << " | Suricata: " << (eve_active ? "active" : "inactive") << "\n\n";
            std::cout << "ACTIVE THREAT SCORES\n";
            for (const auto& entry : database.list_threat_scores()) {
                if (entry.points <= 0) continue;
                std::cout << "  " << entry.ip << " score=" << std::min(100, entry.points)
                          << " risk=" << (entry.points >= 100 ? "CRITICAL" : entry.points >= 60 ? "HIGH" : entry.points >= 30 ? "SUSPICIOUS" : "LOW") << "\n";
            }
            std::cout << "\nLIVE SECURITY STREAM\n" << tail_file("/var/log/copsec/siem_cef.log")
                      << tail_file("/var/log/copsec/agent.log");
            std::cout.flush();
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    if (command == "ban" && argc >= 3 && std::string(argv[2]) == "list") {
        std::string output;
        if (!run_nft_command("list set inet copsec_filter ban_list", output)) {
            std::cerr << "Unable to query ban list.\n";
            return 1;
        }
        if (output.empty() || count_ipv4_entries(output) == 0) {
            std::cout << "No active bans present.\n";
            return 0;
        }
        copsec::DbManager::get_instance().initialize();
        print_ban_table(output);
        return 0;
    }

    if (command == "ban" && argc >= 3 && std::string(argv[2]) == "clear-list") {
        std::string before;
        if (!run_nft_command("list set inet copsec_filter ban_list", before)) {
            std::cerr << nlohmann::json{{"command", "ban clear-list"}, {"success", false},
                {"error", "Unable to query ban list."}}.dump() << '\n';
            return 1;
        }
        const std::size_t flushed = count_ipv4_entries(before);
        std::string output;
        if (!run_nft_command("flush set inet copsec_filter ban_list", output)) {
            std::cerr << nlohmann::json{{"command", "ban clear-list"}, {"success", false},
                {"error", output}}.dump() << '\n';
            return 1;
        }
        std::cout << nlohmann::json{{"command", "ban clear-list"}, {"success", true},
            {"flushed", flushed}, {"history_preserved", true}}.dump() << '\n';
        return 0;
    }

    if (command == "update") {
        const auto executable = std::filesystem::read_symlink("/proc/self/exe");
        const auto project_root = executable.parent_path().parent_path();
        const auto quote = [](const std::filesystem::path& path) { return "'" + path.string() + "'"; };
        const std::string root = quote(project_root);
        if (std::system(("git -C " + root + " pull --ff-only origin main").c_str()) != 0 ||
            std::system(("cmake --build " + quote(project_root / "build") + " --parallel").c_str()) != 0 ||
            std::system(("install -m 0755 " + quote(project_root / "build/copsec") + " /usr/local/bin/copsec && install -m 0755 " + quote(project_root / "build/copsec-cli") + " /usr/local/bin/copsec-cli").c_str()) != 0 ||
            std::system("systemctl restart copsec") != 0) {
            std::cerr << "Update failed.\n";
            return 1;
        }
        std::cout << "CoPSeC updated and restarted.\n";
        return 0;
    }

    if (command == "start" || command == "stop" || command == "restart") {
        const std::string service_action = command + " copsec.service";
        const int result = std::system(("systemctl " + service_action).c_str());
        return result == 0 ? 0 : 1;
    }

    if (command == "config-reload") {
        const pid_t pid = find_daemon_pid();
        if (pid <= 1) {
            std::cerr << "[-] copsec daemon is not running.\n";
            return 1;
        }
        if (kill(pid, SIGHUP) != 0) {
            std::cerr << "[-] Failed to send SIGHUP to PID " << pid << ": "
                      << std::strerror(errno) << "\n";
            return 1;
        }
        std::cout << "[+] SIGHUP signal sent to PID " << pid << ". Rules reloaded.\n";
        return 0;
    }

    if (command == "db-vacuum") {
        auto& database = copsec::DbManager::get_instance();
        if (!database.initialize() || !database.vacuum()) {
            std::cerr << "Database vacuum failed.\n";
            return 1;
        }
        std::cout << "Database vacuum completed.\n";
        return 0;
    }

    if (command == "whitelist") {
        if (argc < 3 || !copsec::DbManager::get_instance().initialize()) {
            print_usage();
            return 1;
        }
        const std::string action = argv[2];
        auto& database = copsec::DbManager::get_instance();
        if (action == "add" && argc >= 4) {
            const std::string description = argc >= 5 ? argv[4] : "cli";
            const bool success = database.add_whitelist(argv[3], description);
            std::cout << (success ? "Whitelist entry added.\n" : "Failed to add whitelist entry.\n");
            return success ? 0 : 1;
        }
        if (action == "remove" && argc >= 4) {
            const bool success = database.remove_whitelist(argv[3]);
            std::cout << (success ? "Whitelist entry removed.\n" : "Whitelist entry not found.\n");
            return success ? 0 : 1;
        }
        if (action == "list") {
            for (const auto& entry : database.list_whitelist()) {
                std::cout << entry.id << "\t" << entry.ip_cidr << "\t"
                          << entry.description << "\t" << entry.added_at << "\n";
            }
            return 0;
        }
        print_usage();
        return 1;
    }

    if (command == "status") {
        std::string output;
        if (!run_nft_command("list set inet copsec_filter ban_list", output)) {
            std::cerr << "Unable to query ban list. Ensure nftables is available and the rule set exists.\n";
            return 1;
        }
        if (output.empty()) {
            std::cout << "No active bans present.\n";
        } else {
            std::cout << output << std::endl;
        }
        return 0;
    }

    if (command == "ban") {
        if (argc < 4) {
            print_usage();
            return 1;
        }

        std::string ip = argv[2];
        std::string seconds = argv[3];
        std::string output;
        std::string nft_cmd = "add element inet copsec_filter ban_list { " + ip + " timeout " + seconds + "s }";
        if (!run_nft_command(nft_cmd, output)) {
            std::cerr << "Failed to ban IP: " << ip << "\n" << output << std::endl;
            return 1;
        }

        std::cout << "Banned IP " << ip << " for " << seconds << " seconds.\n";
        return 0;
    }

    if (command == "unban") {
        if (argc < 3) {
            print_usage();
            return 1;
        }

        std::string ip = argv[2];
        std::string output;
        std::string nft_cmd = "delete element inet copsec_filter ban_list { " + ip + " }";
        if (!run_nft_command(nft_cmd, output)) {
            std::cerr << "Failed to unban IP: " << ip << "\n" << output << std::endl;
            return 1;
        }

        std::cout << "Removed IP " << ip << " from the ban list.\n";
        return 0;
    }

    if (command == "flush") {
        std::string output;
        if (!run_nft_command("flush set inet copsec_filter ban_list", output)) {
            std::cerr << "Failed to flush ban list.\n" << output << std::endl;
            return 1;
        }
        std::cout << "Ban list flushed.\n";
        return 0;
    }

    if (command == "lookup") {
        if (argc < 3) {
            print_usage();
            return 1;
        }

        copsec::ShodanClient client;
        const auto info = client.lookup_host(argv[2]);
        print_host_info(info);
        return 0;
    }

    if (command == "shm") {
        copsec::ShmClient client;
        if (!client.attached()) {
            std::cerr << "Shared memory segment is unavailable. Start the daemon first.\n";
            return 1;
        }
        print_shm_snapshot(client.snapshot());
        return 0;
    }

    if (command == "mitre") {
        if (argc < 3) {
            print_usage();
            return 1;
        }

        bool offline = false;
        std::string taxii_endpoint;
        for (int i = 3; i < argc; ++i) {
            if (std::string(argv[i]) == "--offline") {
                offline = true;
            } else if (std::string(argv[i]) == "--taxii" && i + 1 < argc) {
                taxii_endpoint = argv[++i];
            }
        }

        if (offline) {
            copsec::StixParser parser;
            if (!parser.load_default_offline_dataset()) {
                std::cerr << "Offline MITRE STIX dataset is not available.\n";
                return 1;
            }
            const auto profile = parser.query_technique(argv[2]);
            if (profile.id.empty() && profile.name.empty()) {
                std::cerr << "Technique not found in offline STIX dataset: " << argv[2] << "\n";
                return 1;
            }
            auto actors = parser.actors_for(profile.id);
            print_stix_profile(profile, actors);
            print_mitre_rule_context(argv[2]);
            return 0;
        }

        copsec::MitreEngine engine;
        bool loaded = false;
        if (!taxii_endpoint.empty()) {
            loaded = engine.refresh_from_taxii(taxii_endpoint, "/var/lib/copsec/mitre_attack.json");
        } else {
            loaded = engine.load_stix_json("");
        }
        if (!loaded) {
            std::cerr << "MITRE ATT&CK STIX dataset is unavailable.\n";
            return 1;
        }
        const auto info = engine.lookup_technique(argv[2]);
        if (info.id.empty()) {
            std::cerr << "Technique not found in MITRE ATT&CK STIX dataset: " << argv[2] << "\n";
            return 1;
        }
        print_mitre_info(info);
        print_mitre_rule_context(argv[2]);
        return 0;
    }

    if (command == "fail2ban") {
        if (argc < 3 || std::string(argv[2]) != "status") {
            print_usage();
            return 1;
        }

        copsec::Fail2banEngine engine;
        std::cout << engine.status_report();
        return 0;
    }

    if (command == "suricata") {
        if (argc < 3 || std::string(argv[2]) != "status") {
            print_usage();
            return 1;
        }
        const std::filesystem::path eve_path = "/var/log/suricata/eve.json";
        const std::filesystem::path fast_path = "/var/log/suricata/fast.log";
        const bool eve_active = std::filesystem::is_regular_file(eve_path);
        const bool fast_active = std::filesystem::is_regular_file(fast_path);
        const std::size_t eve_alerts = count_suricata_alerts(eve_path, true);
        const std::size_t fast_alerts = count_suricata_alerts(fast_path, false);
        std::cout << "=== Suricata NIDS Status ===\n";
        std::cout << "EVE Stream: " << eve_path << " [" << (eve_active ? "active" : "inactive/not found") << "]\n";
        std::cout << "Fast Log:   " << fast_path << " [" << (fast_active ? "active" : "inactive/not found") << "]\n";
        std::cout << "Total parsed alerts: " << eve_alerts + fast_alerts << "\n";
        std::cout << "Status: " << ((eve_active || fast_active) ? "monitoring available Suricata streams" : "Suricata logs unavailable") << "\n";
        return 0;
    }

    if (command == "xdp") {
        if (argc < 3 || std::string(argv[2]) != "status") {
            print_usage();
            return 1;
        }
        auto& xdp = copsec::XdpBouncer::get_instance();
        xdp.refresh_kernel_stats();
        std::cout << xdp.status_report();
        return 0;
    }

    if (command == "pcap") {
        if (argc < 3 || std::string(argv[2]) != "list") {
            print_usage();
            return 1;
        }
        auto& pcap = copsec::PcapForensics::get_instance();
        const auto files = pcap.list_pcap_files();
        std::cout << pcap.status_report();
        if (!files.empty()) {
            std::cout << "\nStored PCAP Files:\n";
            for (const auto& file : files) {
                std::cout << "  - " << file << "\n";
            }
        }
        return 0;
    }

    if (command == "purge-pcaps") {
        const auto deleted_count = copsec::PcapManager::purge_all_captures();
        if (deleted_count == std::numeric_limits<std::size_t>::max()) {
            std::cerr << "PCAP purge failed: permission denied or capture reinitialization failed.\n";
            return 1;
        }
        std::cout << "Purged " << deleted_count << " PCAP capture(s).\n";
        return 0;
    }

    print_usage();
    return 1;
}
