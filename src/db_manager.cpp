#include "db_manager.hpp"

#include <sqlite3.h>
#include <nlohmann/json.hpp>

#include <arpa/inet.h>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <ifaddrs.h>
#include <net/if.h>
#include <sstream>

namespace copsec {
namespace {

bool parse_network(const std::string& value, sockaddr_storage& address, sockaddr_storage& mask) {
    const auto slash = value.find('/');
    const std::string ip = slash == std::string::npos ? value : value.substr(0, slash);
    int prefix = -1;
    if (slash != std::string::npos) {
        try {
            prefix = std::stoi(value.substr(slash + 1));
        } catch (...) {
            return false;
        }
    }
    std::memset(&address, 0, sizeof(address));
    std::memset(&mask, 0, sizeof(mask));
    in_addr ipv4{};
    if (inet_pton(AF_INET, ip.c_str(), &ipv4) == 1) {
        if (prefix < 0) prefix = 32;
        if (prefix < 0 || prefix > 32) return false;
        in_addr network = ipv4;
        in_addr network_mask{};
        network_mask.s_addr = prefix == 0 ? 0 : htonl(0xffffffffU << (32 - prefix));
        network.s_addr &= network_mask.s_addr;
        std::memset(&address, 0, sizeof(address));
        std::memset(&mask, 0, sizeof(mask));
        reinterpret_cast<sockaddr_in*>(&address)->sin_family = AF_INET;
        reinterpret_cast<sockaddr_in*>(&address)->sin_addr = network;
        reinterpret_cast<sockaddr_in*>(&mask)->sin_family = AF_INET;
        reinterpret_cast<sockaddr_in*>(&mask)->sin_addr = network_mask;
        return true;
    }
    in6_addr ipv6{};
    if (inet_pton(AF_INET6, ip.c_str(), &ipv6) == 1) {
        if (prefix < 0) prefix = 128;
        if (prefix < 0 || prefix > 128) return false;
        auto network = ipv6;
        in6_addr network_mask{};
        for (int bit = 0; bit < 128; ++bit) {
            const auto byte = bit / 8;
            const auto mask_bit = bit % 8;
            const bool enabled = bit < prefix;
            if (enabled) network_mask.s6_addr[byte] |= static_cast<unsigned char>(0x80U >> mask_bit);
            if (!enabled) network.s6_addr[byte] &= static_cast<unsigned char>(~(0x80U >> mask_bit));
        }
        std::memset(&address, 0, sizeof(address));
        std::memset(&mask, 0, sizeof(mask));
        reinterpret_cast<sockaddr_in6*>(&address)->sin6_family = AF_INET6;
        reinterpret_cast<sockaddr_in6*>(&address)->sin6_addr = network;
        reinterpret_cast<sockaddr_in6*>(&mask)->sin6_family = AF_INET6;
        reinterpret_cast<sockaddr_in6*>(&mask)->sin6_addr = network_mask;
        return true;
    }
    return false;
}

bool address_in_network(const std::string& ip, const std::string& network) {
    sockaddr_storage base{}, mask{};
    if (!parse_network(network, base, mask)) return false;
    in_addr ipv4{};
    if (inet_pton(AF_INET, ip.c_str(), &ipv4) == 1 && base.ss_family == AF_INET) {
        const auto* target_ip = &ipv4;
        const auto* base_ip = reinterpret_cast<const in_addr*>(&base);
        const auto* network_mask = reinterpret_cast<const in_addr*>(&mask);
        return (target_ip->s_addr & network_mask->s_addr) == base_ip->s_addr;
    }
    in6_addr ipv6{};
    if (inet_pton(AF_INET6, ip.c_str(), &ipv6) == 1 && base.ss_family == AF_INET6) {
        const auto* target_ip = &ipv6;
        const auto* base_ip = reinterpret_cast<const in6_addr*>(&base);
        const auto* network_mask = reinterpret_cast<const in6_addr*>(&mask);
        for (std::size_t i = 0; i < 16; ++i) {
            if ((target_ip->s6_addr[i] & network_mask->s6_addr[i]) != base_ip->s6_addr[i]) return false;
        }
        return true;
    }
    return false;
}

std::string local_networks() {
    std::ostringstream result;
    ifaddrs* interfaces = nullptr;
    if (getifaddrs(&interfaces) != 0) return {};
    for (auto* current = interfaces; current; current = current->ifa_next) {
        if (!current->ifa_addr || !current->ifa_netmask || (current->ifa_flags & IFF_LOOPBACK)) continue;
        char address[INET6_ADDRSTRLEN]{};
        char netmask[INET6_ADDRSTRLEN]{};
        const int family = current->ifa_addr->sa_family;
        if (family == AF_INET) {
            inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(current->ifa_addr)->sin_addr, address, sizeof(address));
            inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(current->ifa_netmask)->sin_addr, netmask, sizeof(netmask));
            auto ip = ntohl(reinterpret_cast<sockaddr_in*>(current->ifa_addr)->sin_addr.s_addr);
            auto mask = ntohl(reinterpret_cast<sockaddr_in*>(current->ifa_netmask)->sin_addr.s_addr);
            const auto network = htonl(ip & mask);
            inet_ntop(AF_INET, &network, address, sizeof(address));
            int prefix = 0;
            for (auto bits = mask; bits & 0x80000000U; bits <<= 1) ++prefix;
            result << address << '/' << prefix << '\n';
        } else if (family == AF_INET6) {
            inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(current->ifa_addr)->sin6_addr, address, sizeof(address));
            inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(current->ifa_netmask)->sin6_addr, netmask, sizeof(netmask));
            result << address << '/' << 64 << '\n';
        }
    }
    freeifaddrs(interfaces);
    return result.str();
}

std::string default_gateway() {
    std::ifstream routes("/proc/net/route");
    std::string line;
    std::getline(routes, line);
    while (std::getline(routes, line)) {
        std::istringstream fields(line);
        std::string interface, destination, gateway, flags;
        fields >> interface >> destination >> gateway >> flags;
        if (destination != "00000000" || gateway.empty()) continue;
        unsigned long value = 0;
        std::stringstream(gateway) >> std::hex >> value;
        in_addr address{static_cast<in_addr_t>(value)};
        char text[INET_ADDRSTRLEN]{};
        if (inet_ntop(AF_INET, &address, text, sizeof(text))) return text;
    }
    return {};
}

} // namespace

DbManager& DbManager::get_instance() {
    static DbManager instance;
    return instance;
}

DbManager::~DbManager() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (database_) sqlite3_close(database_);
}

bool DbManager::initialize(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (database_) return true;
    const char* override_path = std::getenv("COPSEC_DB_PATH");
    path_ = (path == "/var/lib/copsec/copsec.db" && override_path && *override_path) ? override_path : path;
    std::error_code error;
    std::filesystem::create_directories(std::filesystem::path(path_).parent_path(), error);
    if (error) return false;
    if (sqlite3_open_v2(path_.c_str(), &database_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr) != SQLITE_OK) {
        if (database_) sqlite3_close(database_);
        database_ = nullptr;
        return false;
    }
    sqlite3_busy_timeout(database_, 5000);
    if (!exec_locked("PRAGMA journal_mode=WAL;") || !exec_locked("PRAGMA synchronous=NORMAL;")) {
        sqlite3_close(database_);
        database_ = nullptr;
        return false;
    }
    if (!create_schema_locked() || !seed_defaults_locked()) {
        sqlite3_close(database_);
        database_ = nullptr;
        return false;
    }
    if (!rebuild_whitelist_cache_locked()) {
        sqlite3_close(database_);
        database_ = nullptr;
        return false;
    }
    return true;
}

bool DbManager::create_schema_locked() {
    return exec_locked("PRAGMA journal_mode=WAL;") && exec_locked(
        "CREATE TABLE IF NOT EXISTS whitelist ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "ip_cidr TEXT UNIQUE NOT NULL,"
        "description TEXT,"
        "added_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);") && exec_locked(
        "CREATE TABLE IF NOT EXISTS incidents ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "ip TEXT, rule_id TEXT, mitre_tactic TEXT, mitre_technique TEXT,"
        "pcap_path TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "mitre_technique_name TEXT, raw_log_payload TEXT, action_taken TEXT, ban_duration INTEGER DEFAULT 0);") && migrate_schema_locked();
}

bool DbManager::migrate_schema_locked() {
    auto has_column = [this](const char* table, const char* column) {
        sqlite3_stmt* statement = nullptr;
        std::string query = "PRAGMA table_info(" + std::string(table) + ");";
        if (sqlite3_prepare_v2(database_, query.c_str(), -1, &statement, nullptr) != SQLITE_OK) return false;
        bool found = false;
        while (sqlite3_step(statement) == SQLITE_ROW) {
            const auto* name = reinterpret_cast<const char*>(sqlite3_column_text(statement, 1));
            if (name && std::string(name) == column) {
                found = true;
                break;
            }
        }
        sqlite3_finalize(statement);
        return found;
    };

    if (has_column("whitelist", "ip_or_cidr") && !has_column("whitelist", "ip_cidr") &&
        !exec_locked("ALTER TABLE whitelist RENAME COLUMN ip_or_cidr TO ip_cidr;")) {
        return false;
    }

    if (has_column("incidents", "mitre_tactics") && !has_column("incidents", "mitre_tactic")) {
        const bool migrated = exec_locked("ALTER TABLE incidents RENAME TO incidents_legacy;") &&
            exec_locked("CREATE TABLE incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, rule_id TEXT, mitre_tactic TEXT, mitre_technique TEXT, pcap_path TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP);") &&
            exec_locked("INSERT INTO incidents(ip, rule_id, mitre_tactic, mitre_technique, pcap_path, timestamp) SELECT ip, rule_id, mitre_tactics, mitre_technique, pcap_path, timestamp FROM incidents_legacy;") &&
            exec_locked("DROP TABLE incidents_legacy;");
        if (!migrated) {
            return false;
        }
    }
    const char* additions[] = {
        "ALTER TABLE incidents ADD COLUMN mitre_technique_name TEXT;",
        "ALTER TABLE incidents ADD COLUMN raw_log_payload TEXT;",
        "ALTER TABLE incidents ADD COLUMN action_taken TEXT;",
        "ALTER TABLE incidents ADD COLUMN ban_duration INTEGER DEFAULT 0;"
    };
    const char* columns[] = {"mitre_technique_name", "raw_log_payload", "action_taken", "ban_duration"};
    for (std::size_t index = 0; index < 4; ++index) {
        if (!has_column("incidents", columns[index]) && !exec_locked(additions[index])) return false;
    }
    return true;
}

bool DbManager::seed_defaults_locked() {
    add_whitelist_locked("127.0.0.1/32", "IPv4 loopback");
    add_whitelist_locked("::1/128", "IPv6 loopback");
    if (const auto gateway = default_gateway(); !gateway.empty()) add_whitelist_locked(gateway + "/32", "default gateway");
    std::istringstream networks(local_networks());
    std::string network;
    while (std::getline(networks, network)) if (!network.empty()) add_whitelist_locked(network, "local interface subnet");
    return true;
}

bool DbManager::add_whitelist_locked(const std::string& value, const std::string& description) {
    sqlite3_stmt* statement = nullptr;
    const char* sql = "INSERT OR IGNORE INTO whitelist(ip_cidr, description) VALUES(?, ?);";
    if (sqlite3_prepare_v2(database_, sql, -1, &statement, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(statement, 1, value.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, description.c_str(), -1, SQLITE_TRANSIENT);
    const bool success = sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    return success;
}

bool DbManager::add_whitelist(const std::string& value, const std::string& description) {
    std::lock_guard<std::mutex> lock(mutex_);
    sockaddr_storage address{}, mask{};
    return database_ && parse_network(value, address, mask) && add_whitelist_locked(value, description) && rebuild_whitelist_cache_locked();
}

bool DbManager::remove_whitelist(const std::string& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!database_) return false;
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(database_, "DELETE FROM whitelist WHERE ip_cidr = ?;", -1, &statement, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(statement, 1, value.c_str(), -1, SQLITE_TRANSIENT);
    const bool success = sqlite3_step(statement) == SQLITE_DONE && sqlite3_changes(database_) > 0;
    sqlite3_finalize(statement);
    if (success) rebuild_whitelist_cache_locked();
    return success;
}

std::vector<WhitelistEntry> DbManager::list_whitelist() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<WhitelistEntry> entries;
    if (!database_) return entries;
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(database_, "SELECT id, ip_cidr, description, added_at FROM whitelist ORDER BY id;", -1, &statement, nullptr) != SQLITE_OK) return entries;
    while (sqlite3_step(statement) == SQLITE_ROW) {
        entries.push_back({sqlite3_column_int64(statement, 0),
            reinterpret_cast<const char*>(sqlite3_column_text(statement, 1)),
            reinterpret_cast<const char*>(sqlite3_column_text(statement, 2)),
            reinterpret_cast<const char*>(sqlite3_column_text(statement, 3))});
    }
    sqlite3_finalize(statement);
    return entries;
}

bool DbManager::is_whitelisted(const std::string& ip) const {
    if (ip.empty() || ip == "127.0.0.1" || ip == "::1" || ip == "localhost" ||
        ip == "::ffff:127.0.0.1" || ip == "0:0:0:0:0:0:0:1") {
        return true;
    }

    in_addr address{};
    if (inet_pton(AF_INET, ip.c_str(), &address) == 1) {
        const uint32_t target = ntohl(address.s_addr);
        // Fast-path: 127.0.0.0/8
        if ((target & 0xFF000000U) == 0x7F000000U) return true;
        // Fast-path: 100.64.0.0/10 (Tailscale CGNAT)
        if ((target & 0xFFC00000U) == 0x64400000U) return true;

        std::lock_guard<std::mutex> lock(mutex_);
        for (int prefix = 0; prefix <= 32; ++prefix) {
            for (const auto& network : ipv4_whitelist_cache_[prefix]) {
                if ((target & network.mask) == network.network) return true;
            }
        }
        return false;
    }

    in6_addr address6{};
    if (inet_pton(AF_INET6, ip.c_str(), &address6) == 1) {
        static const in6_addr loopback_addr = IN6ADDR_LOOPBACK_INIT;
        if (std::memcmp(&address6, &loopback_addr, sizeof(in6_addr)) == 0) {
            return true;
        }
        if (IN6_IS_ADDR_V4MAPPED(&address6)) {
            const uint32_t mapped_ip = ntohl(*reinterpret_cast<const uint32_t*>(&address6.s6_addr[12]));
            if ((mapped_ip & 0xFF000000U) == 0x7F000000U) return true;
            if ((mapped_ip & 0xFFC00000U) == 0x64400000U) return true;
        }
    }

    std::lock_guard<std::mutex> lock(mutex_);
    sqlite3_stmt* statement = nullptr;
    if (!database_ || sqlite3_prepare_v2(database_, "SELECT ip_cidr FROM whitelist WHERE ip_cidr LIKE '%:%';", -1, &statement, nullptr) != SQLITE_OK) return false;
    bool matched = false;
    while (sqlite3_step(statement) == SQLITE_ROW) {
        const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(statement, 0));
        if (value && address_in_network(ip, value)) {
            matched = true;
            break;
        }
    }
    sqlite3_finalize(statement);
    return matched;
}

bool DbManager::rebuild_whitelist_cache_locked() {
    for (auto& bucket : ipv4_whitelist_cache_) bucket.clear();
    if (!database_) return false;

    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(database_, "SELECT ip_cidr FROM whitelist;", -1, &statement, nullptr) != SQLITE_OK) return false;
    while (sqlite3_step(statement) == SQLITE_ROW) {
        const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(statement, 0));
        if (!text) continue;
        sockaddr_storage address{}, mask{};
        if (!parse_network(text, address, mask) || address.ss_family != AF_INET) continue;
        const auto network = ntohl(reinterpret_cast<const sockaddr_in*>(&address)->sin_addr.s_addr);
        const auto network_mask = ntohl(reinterpret_cast<const sockaddr_in*>(&mask)->sin_addr.s_addr);
        int prefix = 0;
        for (uint32_t bits = network_mask; bits & 0x80000000U; bits <<= 1) ++prefix;
        ipv4_whitelist_cache_[prefix].push_back({network, network_mask});
    }
    sqlite3_finalize(statement);
    return true;
}

bool DbManager::record_incident(const std::string& ip, const std::string& rule_id, const std::string& mitre_tactics,
                                const std::string& mitre_technique, int64_t timestamp, const std::string& pcap_path,
                                const std::string& mitre_technique_name, const std::string& raw_log_payload,
                                const std::string& action_taken, int64_t ban_duration) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!database_) return false;
    sqlite3_stmt* statement = nullptr;
    const char* sql = "INSERT INTO incidents(ip, rule_id, mitre_tactic, mitre_technique, pcap_path, timestamp, mitre_technique_name, raw_log_payload, action_taken, ban_duration) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
    if (sqlite3_prepare_v2(database_, sql, -1, &statement, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(statement, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, rule_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 3, mitre_tactics.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 4, mitre_technique.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 5, pcap_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 6, timestamp);
    sqlite3_bind_text(statement, 7, mitre_technique_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 8, raw_log_payload.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 9, action_taken.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 10, ban_duration);
    const bool success = sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    return success;
}

bool DbManager::record_threat_score(const std::string& ip, int points) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!database_ || ip.empty()) return false;
    if (!exec_locked("CREATE TABLE IF NOT EXISTS threat_scores (ip TEXT PRIMARY KEY, points INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL);")) return false;
    sqlite3_stmt* statement = nullptr;
    const char* sql = "INSERT INTO threat_scores(ip, points, updated_at) VALUES(?, MIN(100, ?), strftime('%s','now')) "
                      "ON CONFLICT(ip) DO UPDATE SET points = MIN(100, points + excluded.points), updated_at = excluded.updated_at;";
    if (sqlite3_prepare_v2(database_, sql, -1, &statement, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(statement, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 2, points);
    const bool success = sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    return success;
}

std::vector<ThreatScoreEntry> DbManager::list_threat_scores() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ThreatScoreEntry> result;
    if (!database_) return result;
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(database_, "SELECT ip, points, updated_at FROM threat_scores WHERE points > 0 ORDER BY points DESC;", -1, &statement, nullptr) != SQLITE_OK) return result;
    while (sqlite3_step(statement) == SQLITE_ROW) {
        const auto* ip = reinterpret_cast<const char*>(sqlite3_column_text(statement, 0));
        result.push_back({ip ? ip : "", sqlite3_column_int(statement, 1), sqlite3_column_int64(statement, 2)});
    }
    sqlite3_finalize(statement);
    return result;
}

std::vector<RecentIncident> DbManager::recent_incidents(std::size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<RecentIncident> incidents;
    if (!database_ || limit == 0) return incidents;

    sqlite3_stmt* statement = nullptr;
    const char* sql = "SELECT CAST(timestamp AS TEXT), ip, rule_id, mitre_tactic, mitre_technique, mitre_technique_name, raw_log_payload, action_taken, ban_duration "
                      "FROM incidents ORDER BY id DESC LIMIT ?;";
    if (sqlite3_prepare_v2(database_, sql, -1, &statement, nullptr) != SQLITE_OK) return incidents;
    sqlite3_bind_int64(statement, 1, static_cast<sqlite3_int64>(limit));
    while (sqlite3_step(statement) == SQLITE_ROW) {
        const auto text = [statement](int column) {
            const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(statement, column));
            return value ? std::string(value) : std::string{};
        };
        incidents.push_back({text(0), text(1), text(2), text(3), text(4), text(5),
                     text(7), text(6), sqlite3_column_int64(statement, 8)});
    }
    sqlite3_finalize(statement);
    return incidents;
}

std::string DbManager::get_recent_events(int limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    nlohmann::json events = nlohmann::json::array();
    if (!database_ || limit <= 0) return events.dump();

    // The persisted schema predates the public API names; aliases keep the
    // REST contract stable without requiring a destructive migration.
    sqlite3_stmt* statement = nullptr;
    const char* sql =
        "SELECT CAST(timestamp AS TEXT), ip AS source_ip, rule_id, "
        "mitre_tactic, mitre_technique, mitre_technique_name, raw_log_payload, action_taken, ban_duration "
        "FROM incidents ORDER BY id DESC LIMIT ?;";
    if (sqlite3_prepare_v2(database_, sql, -1, &statement, nullptr) != SQLITE_OK) return events.dump();
    sqlite3_bind_int(statement, 1, limit);
    while (sqlite3_step(statement) == SQLITE_ROW) {
        const auto text = [statement](int column) {
            const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(statement, column));
            return value ? std::string(value) : std::string{};
        };
        events.push_back({
            {"timestamp", text(0)}, {"source_ip", text(1)},
            {"rule_id", text(2)}, {"mitre_tactic", text(3)},
            {"mitre_technique_id", text(4)}, {"mitre_technique_name", text(5)},
            {"raw_log_payload", text(6)}, {"action_taken", text(7)},
            {"ban_duration", sqlite3_column_int64(statement, 8)}
        });
    }
    sqlite3_finalize(statement);
    return events.dump();
}

bool DbManager::vacuum() {
    std::lock_guard<std::mutex> lock(mutex_);
    return database_ && exec_locked("VACUUM;");
}

bool DbManager::initialized() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return database_ != nullptr;
}

bool DbManager::exec_locked(const char* sql) const {
    char* error = nullptr;
    const bool success = sqlite3_exec(database_, sql, nullptr, nullptr, &error) == SQLITE_OK;
    sqlite3_free(error);
    return success;
}

} // namespace copsec