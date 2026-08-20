#pragma once

#include "mitre_engine.hpp"

#include <chrono>
#include <ctime>
#include <algorithm>
#include <cctype>
#include <string>

namespace copsec {

inline std::string telemetry_tactic_slug(std::string tactic) {
    if (tactic == "N/A" || tactic.empty()) return "N/A";
    std::transform(tactic.begin(), tactic.end(), tactic.begin(), [](unsigned char character) {
        return character == ' ' ? '-' : static_cast<char>(std::tolower(character));
    });
    return tactic;
}

struct TelemetryEvent {
    std::string timestamp;
    std::string event_type;
    std::string src_ip;
    std::string rule_id;
    int ban_duration_seconds = 0;
    MitreMetadata mitre{"N/A", "N/A", "N/A", "N/A", ""};

    nlohmann::json to_json() const {
        return {
            {"timestamp", timestamp},
            {"event_type", event_type},
            {"src_ip", src_ip},
            {"rule_id", rule_id},
            {"ban_duration_seconds", ban_duration_seconds},
            {"mitre", {
                {"tactic", telemetry_tactic_slug(mitre.tactic)},
                {"tactic_id", mitre.tactic_id.empty() ? "N/A" : mitre.tactic_id},
                {"technique_id", mitre.technique_id.empty() ? "N/A" : mitre.technique_id},
                {"technique_name", mitre.technique_name.empty() ? "N/A" : mitre.technique_name},
                {"url", mitre.url}
            }}
        };
    }
};

inline std::string telemetry_timestamp() {
    const auto now = std::chrono::system_clock::now();
    const auto seconds = std::chrono::time_point_cast<std::chrono::seconds>(now);
    std::time_t current = static_cast<std::time_t>(seconds.time_since_epoch().count());
    std::tm utc{};
    gmtime_r(&current, &utc);
    char buffer[32]{};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &utc);
    return buffer;
}

inline nlohmann::json normalize_telemetry(const std::string& event_type,
                                           const nlohmann::json& source,
                                           const MitreEngine& engine) {
    TelemetryEvent event;
    event.timestamp = source.value("timestamp", telemetry_timestamp());
    event.event_type = event_type;
    event.src_ip = source.value("src_ip", source.value("ip", ""));
    event.rule_id = source.value("rule_id", "");
    event.ban_duration_seconds = source.value("ban_duration_seconds", source.value("duration", 0));
    event.mitre = engine.get_technique(event.rule_id);
    if (event.mitre.tactic == "Unknown Tactic") event.mitre.tactic = "N/A";
    if (event.mitre.tactic_id == "Unknown Tactic ID") event.mitre.tactic_id = "N/A";
    if (event.mitre.technique_id == "Unknown Technique ID") event.mitre.technique_id = "N/A";
    if (event.mitre.technique_name == "Unknown Technique Name") event.mitre.technique_name = "N/A";
    if (source.contains("mitre") && source["mitre"].is_object()) {
        const auto& mitre = source["mitre"];
        event.mitre.tactic = mitre.value("tactic", event.mitre.tactic);
        event.mitre.technique_id = mitre.value("technique_id", event.mitre.technique_id);
        event.mitre.technique_name = mitre.value("technique_name", event.mitre.technique_name);
    }
    event.mitre.tactic = source.value("mitre_tactic", event.mitre.tactic);
    event.mitre.technique_id = source.value("mitre_technique_id", source.value("mitre_technique", event.mitre.technique_id));
    event.mitre.technique_name = source.value("mitre_technique_name", event.mitre.technique_name);
    return engine.enrich_event(event.to_json());
}

} // namespace copsec
