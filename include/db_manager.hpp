#pragma once

#include <cstdint>
#include <array>
#include <mutex>
#include <string>
#include <vector>

struct sqlite3;

namespace copsec {

struct WhitelistEntry {
    int64_t id = 0;
    std::string ip_cidr;
    std::string description;
    std::string added_at;
};

struct RecentIncident {
    std::string timestamp;
    std::string src_ip;
    std::string rule_id;
    std::string mitre_tactic;
    std::string mitre_technique_id;
    std::string mitre_technique_name;
    std::string action_taken;
    std::string raw_log_payload;
    int64_t ban_duration = 0;
};

struct ThreatScoreEntry {
    std::string ip;
    int points = 0;
    int64_t updated_at = 0;
};

class DbManager {
public:
    static DbManager& get_instance();

    DbManager(const DbManager&) = delete;
    DbManager& operator=(const DbManager&) = delete;

    bool initialize(const std::string& path = "/var/lib/copsec/copsec.db");
    bool is_whitelisted(const std::string& ip) const;
    bool add_whitelist(const std::string& ip_cidr, const std::string& description = "manual");
    bool remove_whitelist(const std::string& ip_cidr);
    std::vector<WhitelistEntry> list_whitelist() const;
    bool record_incident(const std::string& ip,
                         const std::string& rule_id,
                         const std::string& mitre_tactics,
                         const std::string& mitre_technique,
                         int64_t timestamp,
                         const std::string& pcap_path,
                         const std::string& mitre_technique_name = {},
                         const std::string& raw_log_payload = {},
                         const std::string& action_taken = {},
                         int64_t ban_duration = 0);
    bool record_threat_score(const std::string& ip, int points);
    std::vector<ThreatScoreEntry> list_threat_scores() const;
    std::vector<RecentIncident> recent_incidents(std::size_t limit = 50) const;
    std::string get_recent_events(int limit = 50) const;
    bool vacuum();

    bool initialized() const;
    ~DbManager();

private:
    DbManager() = default;
    bool create_schema_locked();
    bool migrate_schema_locked();
    bool seed_defaults_locked();
    bool add_whitelist_locked(const std::string& value, const std::string& description);
    bool rebuild_whitelist_cache_locked();
    bool exec_locked(const char* sql) const;

    struct IPv4Network {
        uint32_t network = 0;
        uint32_t mask = 0;
    };

    mutable std::mutex mutex_;
    sqlite3* database_ = nullptr;
    std::string path_;
    std::array<std::vector<IPv4Network>, 33> ipv4_whitelist_cache_;
};

} // namespace copsec