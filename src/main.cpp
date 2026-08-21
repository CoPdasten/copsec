#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <thread>
#include <vector>

#include "bouncer.hpp"
#include "db_manager.hpp"
#include "anti_evasion.hpp"
#include "ebpf_monitor.hpp"
#include "process_monitor.hpp"
#include "siem_exporter.hpp"
#include "decoy_engine.hpp"
#include "logger.hpp"
#include "mitre.hpp"
#include "mitre_engine.hpp"
#include "normalizer.hpp"
#include "parser.hpp"
#include "rate_limiter.hpp"
#include "pcap_capture.hpp"
#include "pcap_manager.hpp"
#include "shm_ipc.hpp"
#include "suricata_watcher.hpp"
#include "shm_guard.hpp"
#include "sync.hpp"
#include "soar_worker.hpp"
#include "whitelist.hpp"
#include "xdp_bouncer.hpp"

// Global sync constructs for signal handling
std::atomic<bool> g_running{true};
volatile std::sig_atomic_t g_reload_requested = 0;
std::mutex g_signal_mutex;
std::condition_variable g_signal_cv;

void signal_handler(int signal) {
    if (signal == SIGHUP) {
        g_reload_requested = 1;
    } else if (signal == SIGINT || signal == SIGTERM) {
        g_running = false;
    }
}

bool install_signal_handlers() {
    struct sigaction action {};
    sigemptyset(&action.sa_mask);
    action.sa_handler = signal_handler;
    action.sa_flags = 0;
    return sigaction(SIGINT, &action, nullptr) == 0 &&
           sigaction(SIGTERM, &action, nullptr) == 0 &&
           sigaction(SIGHUP, &action, nullptr) == 0;
}

// Helper to find rules.json path
std::string find_rules_config() {
    std::vector<std::string> paths = {
        "config/rules.json",
        "../config/rules.json",
        "./rules.json",
        "/etc/copsec/rules.json"
    };
    for (const auto& path : paths) {
        if (std::filesystem::exists(path)) {
            return path;
        }
    }
    return "";
}

bool load_agent_config(copsec::SoarWorker::Settings& settings, copsec::DecoyEngine::Settings& decoy_settings) {
    const std::vector<std::string> paths = {
        "config/config.json", "../config/config.json", "/etc/copsec/config.json"
    };
    for (const auto& path : paths) {
        std::ifstream input(path);
        if (!input.is_open()) continue;
        try {
            nlohmann::json document;
            input >> document;
            settings.enable_tor_blocklist = document.value("enable_tor_blocklist", false);
            decoy_settings.enabled = document.value("decoy_engine_enabled", true);
            if (document.contains("decoy_paths") && document["decoy_paths"].is_array()) {
                for (const auto& path : document["decoy_paths"]) {
                    if (path.is_string()) decoy_settings.paths.push_back(path.get<std::string>());
                }
            }
            copsec::SiemExporter::Settings siem;
            siem.enabled = document.value("siem_export_enabled", false);
            siem.host = document.value("siem_host", "127.0.0.1");
            siem.port = document.value("siem_port", static_cast<std::uint16_t>(514));
            siem.format = document.value("siem_format", "cef");
            copsec::SiemExporter::instance().configure(std::move(siem));
            return true;
        } catch (const std::exception& exception) {
            std::cerr << "Warning: unable to parse agent config " << path << ": " << exception.what() << "\n";
            return false;
        }
    }
    return false;
}

bool load_rules_source(const std::string& source, nlohmann::json& output) {
    output = nlohmann::json{{"rules", nlohmann::json::array()}};
    try {
        const std::filesystem::path source_path(source);
        if (source_path.extension() == ".yaml" || source_path.extension() == ".yml") {
            std::ifstream yaml(source);
            if (!yaml.is_open() || yaml.peek() == std::ifstream::traits_type::eof()) return false;
            const std::string rules_directory = "/etc/copsec/rules";
            return load_rules_source(rules_directory, output);
        }
        if (std::filesystem::is_regular_file(source)) {
            std::ifstream input(source);
            if (!input.is_open()) return false;
            nlohmann::json document;
            input >> document;
            if (!document.contains("rules") || !document["rules"].is_array()) return false;
            output["rules"] = document["rules"];
            if (document.contains("monitored_paths") && document["monitored_paths"].is_array()) {
                output["monitored_paths"] = document["monitored_paths"];
            }
            return true;
        }

        if (!std::filesystem::is_directory(source)) return false;
        for (const auto& entry : std::filesystem::directory_iterator(source)) {
            if (!entry.is_regular_file() || entry.path().extension() != ".json") continue;
            std::ifstream input(entry.path());
            if (!input.is_open()) return false;
            nlohmann::json document;
            input >> document;
            if (!document.contains("rules") || !document["rules"].is_array()) return false;
            for (const auto& rule : document["rules"]) output["rules"].push_back(rule);
        }
        return !output["rules"].empty();
    } catch (const std::exception&) {
        return false;
    }
}

std::string resolve_rules_source(int argc, char** argv) {
    std::string config_path;
    for (int index = 1; index + 1 < argc; ++index) {
        if (std::string(argv[index]) == "--config") {
            config_path = argv[index + 1];
            break;
        }
    }
    if (config_path.empty()) config_path = find_rules_config();
    if (std::filesystem::path(config_path).extension() == ".yaml" ||
        std::filesystem::path(config_path).extension() == ".yml") {
        const std::string rules_directory = "/etc/copsec/rules";
        if (std::filesystem::is_directory(rules_directory)) return config_path;
        return find_rules_config();
    }
    return config_path;
}

// Helper to find whitelist.json path
std::string find_whitelist_config() {
    std::vector<std::string> paths = {
        "config/whitelist.json",
        "../config/whitelist.json",
        "./whitelist.json",
        "/etc/copsec/whitelist.json"
    };
    for (const auto& path : paths) {
        if (std::filesystem::exists(path)) {
            return path;
        }
    }
    return "";
}

int main(int argc, char** argv) {
    if (!install_signal_handlers()) {
        return 1;
    }

    copsec::Logger::get_instance().init("/var/log/copsec/agent.log");
    copsec::Logger::get_instance().log(copsec::LogLevel::INFO, "AGENT_STARTUP",
        "CoPSeC Agent (CoPdasten Security) starting up...");

    if (!copsec::ShmGuard().configured()) {
        copsec::Logger::get_instance().log(copsec::LogLevel::ERR, "SHM_HMAC_CONFIG",
            "COPSEC_SHM_HMAC_KEY is not configured; refusing to start without SHM integrity protection.");
        copsec::Logger::get_instance().shutdown();
        return 1;
    }

    if (!copsec::DbManager::get_instance().initialize()) {
        copsec::Logger::get_instance().log(copsec::LogLevel::ERR, "DB_INIT",
            "Failed to initialize persistent database at /var/lib/copsec/copsec.db.");
        copsec::Logger::get_instance().shutdown();
        return 1;
    }

    auto* shm_server = &copsec::ShmServer::get_instance();
    copsec::Logger::get_instance().log(copsec::LogLevel::INFO, "SHM_INIT",
        "Shared memory segment " + shm_server->name() + " ready for telemetry.");

    WhitelistManager whitelist_mgr;
    std::string whitelist_path = find_whitelist_config();
    if (!whitelist_path.empty()) {
        if (whitelist_mgr.load_whitelist(whitelist_path)) {
            copsec::Logger::get_instance().log(copsec::LogLevel::INFO, "WHITELIST_LOADED",
                "Loaded trusted CIDRs from: " + whitelist_path);
        } else {
            copsec::Logger::get_instance().log(copsec::LogLevel::WARN, "WHITELIST_WARN",
                "Failed to parse whitelist config: " + whitelist_path);
        }
    } else {
        copsec::Logger::get_instance().log(copsec::LogLevel::INFO, "WHITELIST_INFO",
            "No whitelist.json found, continuing without static IP exceptions.");
    }

    const std::string rules_source = resolve_rules_source(argc, argv);
    if (rules_source.empty()) {
        copsec::Logger::get_instance().log(copsec::LogLevel::ERR, "CONFIG_ERROR",
            "Could not locate rules.json configuration file.");
        copsec::Logger::get_instance().shutdown();
        return 1;
    }

    copsec::Logger::get_instance().log(copsec::LogLevel::INFO, "CONFIG_LOAD",
        "Loading configuration rules from: " + rules_source);

    nlohmann::json config_json;
    if (!load_rules_source(rules_source, config_json)) {
        copsec::Logger::get_instance().log(copsec::LogLevel::ERR, "CONFIG_ERROR",
            "Failed to load detection rules from: " + rules_source);
        copsec::Logger::get_instance().shutdown();
        return 1;
    }

    copsec::MitreEngine mitre_engine;
    if (!mitre_engine.initialize(config_json)) {
        copsec::Logger::get_instance().log(copsec::LogLevel::ERR, "MITRE_ERROR",
            "Failed to load MITRE ATT&CK mapping database from rules config.");
        copsec::Logger::get_instance().shutdown();
        return 1;
    }

    copsec::Bouncer bouncer;
    if (!bouncer.init_nftables()) {
        copsec::Logger::get_instance().log(copsec::LogLevel::ERR, "BOUNCER_ERROR",
            "Failed to initialize nftables tables or sets. Bouncer operation compromised.");
    }

    shm_server->update_active_bans(bouncer.active_bans().size());

    copsec::SoarWorker::Settings soar_settings;
    copsec::DecoyEngine::Settings decoy_settings;
    const bool agent_config_loaded = load_agent_config(soar_settings, decoy_settings);
    copsec::Logger::get_instance().log(copsec::LogLevel::INFO, "CONFIG_LOAD",
        std::string("Agent config ") + (agent_config_loaded ? "loaded" :
            "not found; using secure defaults") + ". Tor blocklist=" +
        (soar_settings.enable_tor_blocklist ? "enabled" : "disabled"));
    copsec::SoarWorker soar_worker(bouncer, std::move(soar_settings));
    bouncer.set_ban_observer([&soar_worker](const std::string& ip, int duration, const std::string& rule_id) {
        soar_worker.on_ban_decision(ip, duration, rule_id);
    });
    soar_worker.start();
    copsec::AntiEvasion anti_evasion([&bouncer](const std::string& ip, int duration, const std::string& rule_id) {
        bouncer.ban_ip(ip, duration, rule_id);
    });

    // Initialize enterprise components
    auto& xdp_bouncer = copsec::XdpBouncer::get_instance();
    xdp_bouncer.initialize({"eth0", "ens0", "wlan0"});
    copsec::Logger::get_instance().log(copsec::LogLevel::INFO, "XDP_INIT",
        "eBPF/XDP packet bouncer initialized (nftables fallback active).");

    copsec::EbpfMonitor ebpf_monitor;
    copsec::ProcessMonitor process_monitor(ebpf_monitor);
    process_monitor.start();
    ebpf_monitor.start();

    auto& pcap_forensics = copsec::PcapForensics::get_instance();
    auto& pcap_manager = copsec::PcapManager::get_instance();
    pcap_manager.initialize();
    copsec::PcapManager::ensure_capture_directories();
    pcap_forensics.start("any");
    if (pcap_forensics.initialize()) {
        copsec::Logger::get_instance().log(copsec::LogLevel::INFO, "PCAP_INIT",
            "Forensic PCAP capture ready.");
    }

    copsec::LogWatcher watcher(bouncer, *shm_server, decoy_settings);
    if (!watcher.load_rules(config_json)) {
        copsec::Logger::get_instance().log(copsec::LogLevel::ERR, "PARSER_ERROR",
            "Failed to load rules into LogWatcher parser.");
        copsec::Logger::get_instance().shutdown();
        return 1;
    }

    if (!watcher.start()) {
        copsec::Logger::get_instance().log(copsec::LogLevel::ERR, "PARSER_ERROR",
            "Failed to start LogWatcher parser thread.");
        copsec::Logger::get_instance().shutdown();
        return 1;
    }
    shm_server->update_rule_count(watcher.rule_count());

    std::thread shm_maintenance_thread([&bouncer, shm_server]() {
        while (g_running) {
            shm_server->update_active_bans(bouncer.active_bans().size());
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });

    std::thread sync_thread([&bouncer, shm_server]() {
        copsec::Logger::get_instance().log(copsec::LogLevel::INFO, "SYNC_START",
            "Central API Crowd Intelligence sync thread initiated.");

        while (g_running) {
            std::vector<std::string> global_bans = copsec::SyncModule::pull_global_blocklist(
                "http://127.0.0.1:8080/api/v1/blocklist/sync");
            for (const auto& ip : global_bans) {
                bouncer.ban_ip(ip, 86400);
                shm_server->record_event(ip, "sync_global_blocklist", 86400, std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
                shm_server->increment_total_bans();
            }
            std::this_thread::sleep_for(std::chrono::seconds(30));
        }
    });

    copsec::Logger::get_instance().log(copsec::LogLevel::INFO, "AGENT_READY",
        "CoPSeC threat prevention agent is ready and running. Waiting for events.");

    while (g_running) {
        std::unique_lock<std::mutex> lock(g_signal_mutex);
        g_signal_cv.wait_for(lock, std::chrono::seconds(1), []() {
            return !g_running || g_reload_requested != 0;
        });
        lock.unlock();

        if (!g_running) break;
        g_reload_requested = 0;

        nlohmann::json reloaded_config;
        if (load_rules_source(rules_source, reloaded_config) &&
            mitre_engine.initialize(reloaded_config) &&
            watcher.reload_rules(reloaded_config)) {
            config_json = std::move(reloaded_config);
            shm_server->update_rule_count(watcher.rule_count());
            copsec::Logger::get_instance().log(copsec::LogLevel::INFO, "CONFIG_RELOADED",
                "Detection rules reloaded successfully. Active rules: " +
                std::to_string(watcher.rule_count()));
        } else {
            copsec::Logger::get_instance().log(copsec::LogLevel::ERR, "CONFIG_RELOAD_FAILED",
                "Detection rule reload failed; previous rules remain active.");
        }
    }

    copsec::Logger::get_instance().log(copsec::LogLevel::INFO, "AGENT_SHUTDOWN",
        "Shutdown signal intercepted. Stopping watch threads...");

    watcher.stop();
    process_monitor.stop();
    ebpf_monitor.stop();
    pcap_forensics.stop();
    pcap_manager.shutdown();
    soar_worker.stop();

    if (sync_thread.joinable()) {
        sync_thread.join();
    }
    if (shm_maintenance_thread.joinable()) {
        shm_maintenance_thread.join();
    }

    copsec::Logger::get_instance().log(copsec::LogLevel::INFO, "AGENT_SHUTDOWN",
        "Threads stopped. Active bans remain in kernel nftables space. Exiting cleanly.");

    copsec::Logger::get_instance().shutdown();
    return 0;
}