#include "decoy_engine.hpp"
#include "penalty_engine.hpp"
#include "shm_ipc.hpp"
#include "siem_exporter.hpp"

#include <algorithm>
#include <cctype>
#include <regex>
#include <utility>

namespace copsec {

const std::vector<std::string>& DecoyEngine::default_paths() {
    static const std::vector<std::string> paths = {
        "/.env", "/.git/config", "/admin_v2", "/config.json.bak", "/wp-config.php.bak",
        "/backup.sql", "/phpmyadmin", "/db_backup.sql", "/hidden_admin_decoy"
    };
    return paths;
}

DecoyEngine::DecoyEngine(PenaltyEngine& penalty_engine, ShmServer& shm_server, Settings settings)
    : penalty_engine_(penalty_engine), shm_server_(shm_server), settings_(std::move(settings)) {
    if (settings_.paths.empty()) settings_.paths = default_paths();
}

bool DecoyEngine::matches(const std::string& request_path, std::string& matched_path) const {
    matched_path.clear();
    if (!settings_.enabled || request_path.empty()) return false;
    std::string path = request_path;
    const auto query = path.find('?');
    if (query != std::string::npos) path.resize(query);
    for (const auto& decoy : settings_.paths) {
        if (path == decoy || (path.size() > decoy.size() && path.rfind(decoy + "/", 0) == 0)) {
            matched_path = decoy;
            return true;
        }
    }
    return false;
}

bool DecoyEngine::inspect_request(const std::string& ip, const std::string& request_path) {
    if (!settings_.enabled || ip.empty()) return false;
    std::string decoy_path;
    if (!matches(request_path, decoy_path)) return false;

    const std::string details = "Accessed decoy path: " + decoy_path;
    penalty_engine_.record(ip, 100, "decoy-trap", request_path);
    shm_server_.increment_threats(1);
    SiemExporter::instance().export_event("DECOY_TRAP_TRIGGERED", "Honeypot Endpoint Accessed", 10,
        ip, "FULL_BAN", "mitre=T1595 (Active Scanning) " + details);
    return true;
}

bool DecoyEngine::inspect(const std::string& ip, const std::string& request_line) {
    static const std::regex request_pattern(
        R"(^\s*\"?\s*(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT)\s+([^\s\"]+))",
        std::regex_constants::icase);
    std::smatch match;
    return std::regex_search(request_line, match, request_pattern) &&
        inspect_request(ip, match[1].str());
}

} // namespace copsec
