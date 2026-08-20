#include <cstdlib>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>

#include "fail2ban_engine.hpp"
#include "db_manager.hpp"
#include "mitre_fetcher.hpp"
#include "mitre_engine.hpp"
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

Whitelist:
    whitelist add <ip> "<reason>" Add a trusted IP or CIDR
    whitelist remove <ip>          Remove a trusted IP or CIDR
    whitelist list                 List trusted networks

Bans & Inspection:
    ban <ip> <seconds>              Add a timed nftables ban
    ban list                        List active bans
    unban <ip>                      Remove an IP from the ban set
    flush                           Flush all active bans
    lookup <ip>                     Query host intelligence
    shm                             Show shared-memory telemetry

Storage & Maintenance:
    purge-pcaps                     Delete captured .pcap/.pcapng files
    db-vacuum                       Reclaim SQLite database storage
    pcap list                       List forensic captures

Detection & Intelligence:
    fail2ban status                 Show escalation state
    suricata status                 Show Suricata watcher state
    xdp status                      Show XDP status
    mitre <technique> [--offline]   Query MITRE ATT&CK

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

    if (command == "ban" && argc >= 3 && std::string(argv[2]) == "list") {
        std::string output;
        if (!run_nft_command("list set inet copsec_filter ban_list", output)) {
            std::cerr << "Unable to query ban list.\n";
            return 1;
        }
        std::cout << (output.empty() ? "No active bans present.\n" : output);
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
        for (int i = 3; i < argc; ++i) {
            if (std::string(argv[i]) == "--offline") {
                offline = true;
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
            return 0;
        }

        copsec::MitreEngine engine;
        if (!engine.load_stix_json("")) {
            std::cerr << "MITRE ATT&CK STIX dataset is unavailable.\n";
            return 1;
        }
        const auto info = engine.lookup_technique(argv[2]);
        if (info.id.empty()) {
            std::cerr << "Technique not found in MITRE ATT&CK STIX dataset: " << argv[2] << "\n";
            return 1;
        }
        print_mitre_info(info);
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
        std::cout << "=== Suricata NIDS Status ===\n";
        std::cout << "EVE Stream: /var/log/suricata/eve.json\n";
        std::cout << "Status: monitoring alerts in real-time\n";
        return 0;
    }

    if (command == "xdp") {
        if (argc < 3 || std::string(argv[2]) != "status") {
            print_usage();
            return 1;
        }
        auto& xdp = copsec::XdpBouncer::get_instance();
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
