#include "mitre_engine.hpp"

#include "logger.hpp"

#include <filesystem>
#include <fstream>
#include <vector>
#include <algorithm>
#include <cctype>
#include <unordered_map>

namespace copsec {

namespace {

std::vector<std::filesystem::path> candidate_paths(const std::string& provided_path) {
    std::vector<std::filesystem::path> paths;
    if (!provided_path.empty()) paths.emplace_back(provided_path);
    paths.emplace_back("/usr/share/copsec/mitre_attack.json");
    paths.emplace_back("/var/lib/copsec/mitre_attack.json");
    paths.emplace_back("config/mitre_attack.json");
    return paths;
}

std::string tactic_id_for(const std::string& tactic) {
    static const std::unordered_map<std::string, std::string> ids = {
        {"reconnaissance", "TA0043"}, {"resource development", "TA0042"},
        {"initial access", "TA0001"}, {"execution", "TA0002"},
        {"persistence", "TA0003"}, {"privilege escalation", "TA0004"},
        {"defense evasion", "TA0005"}, {"credential access", "TA0006"},
        {"discovery", "TA0007"}, {"lateral movement", "TA0008"},
        {"collection", "TA0009"}, {"command and control", "TA0011"},
        {"exfiltration", "TA0010"}, {"impact", "TA0040"}
    };
    std::string normalized = tactic;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    const auto found = ids.find(normalized);
    return found == ids.end() ? "N/A" : found->second;
}

std::string technique_url_for(const std::string& technique_id) {
    if (technique_id.empty() || technique_id == "N/A") return {};
    const auto separator = technique_id.find('.');
    if (separator == std::string::npos) return "https://attack.mitre.org/techniques/" + technique_id + "/";
    return "https://attack.mitre.org/techniques/" + technique_id.substr(0, separator) + "/" + technique_id.substr(separator + 1) + "/";
}

} // namespace

bool MitreEngine::initialize(const nlohmann::json& rules_json) {
    MitreMapper& mapper = MitreMapper::get_instance();
    mapper.register_metadata("sqli-attempt", {"Initial Access", "TA0001", "T1190", "Exploit Public-Facing Application", "https://attack.mitre.org/techniques/T1190/"});
    mapper.register_metadata("ssh-bruteforce", {"Credential Access", "TA0006", "T1110.001", "Password Guessing", "https://attack.mitre.org/techniques/T1110/001/"});
    mapper.register_metadata("sudo-priv-esc", {"Privilege Escalation", "TA0004", "T1548.003", "Sudo and Sudo Caching", "https://attack.mitre.org/techniques/T1548/003/"});
    mapper.register_metadata("honeypot-hit", {"Discovery", "TA0007", "T1083", "File and Directory Discovery", "https://attack.mitre.org/techniques/T1083/"});
    mapper.register_metadata("honeypot", {"Discovery", "TA0007", "T1083", "File and Directory Discovery", "https://attack.mitre.org/techniques/T1083/"});
    return mapper.load_from_rules_json(rules_json);
}

MitreMetadata MitreEngine::mapping_for(const std::string& rule_id) const {
    return MitreMapper::get_instance().get_metadata(rule_id);
}

MitreMetadata MitreEngine::get_technique(const std::string& rule_id) const {
    return mapping_for(rule_id);
}

nlohmann::json MitreEngine::enrich_event(const nlohmann::json& event) const {
    nlohmann::json enriched = event;
    const std::string rule_id = event.value("rule_id", "");
    MitreMetadata metadata = get_technique(rule_id);
    if (event.contains("mitre") && event["mitre"].is_object()) {
        const auto& supplied = event["mitre"];
        metadata.tactic = supplied.value("tactic", metadata.tactic);
        metadata.tactic_id = supplied.value("tactic_id", metadata.tactic_id);
        metadata.technique_id = supplied.value("technique_id", metadata.technique_id);
        metadata.technique_name = supplied.value("technique_name", metadata.technique_name);
        metadata.url = supplied.value("url", metadata.url);
    }
    const std::string supplied_technique = event.value("mitre_technique_id", event.value("mitre_technique", ""));
    if (!supplied_technique.empty() && supplied_technique != "N/A") metadata.technique_id = supplied_technique;

    const auto stix = lookup_technique(metadata.technique_id);
    if (!stix.name.empty()) metadata.technique_name = stix.name;
    if (!metadata.tactic_id.empty() && metadata.tactic_id != "N/A") {
        // Keep the explicit rule mapping when present; STIX phase names remain useful as fallback.
    } else if (!metadata.tactic.empty()) {
        metadata.tactic_id = tactic_id_for(metadata.tactic);
    }
    if (metadata.technique_name.empty() || metadata.technique_name == "Unknown Technique Name") metadata.technique_name = "N/A";
    if (metadata.tactic.empty() || metadata.tactic == "Unknown Tactic") metadata.tactic = "N/A";
    if (metadata.tactic_id.empty() || metadata.tactic_id == "Unknown Tactic ID") metadata.tactic_id = "N/A";
    if (metadata.technique_id.empty() || metadata.technique_id == "Unknown Technique ID") metadata.technique_id = "N/A";
    metadata.url = technique_url_for(metadata.technique_id);

    enriched["mitre_tactic"] = metadata.tactic;
    enriched["mitre_tactic_id"] = metadata.tactic_id;
    enriched["mitre_technique_id"] = metadata.technique_id;
    enriched["mitre_technique_name"] = metadata.technique_name;
    enriched["mitre_url"] = metadata.url;
    enriched["mitre"] = {
        {"tactic", metadata.tactic}, {"tactic_id", metadata.tactic_id},
        {"technique_id", metadata.technique_id}, {"technique_name", metadata.technique_name},
        {"url", metadata.url}
    };
    return enriched;
}

bool MitreEngine::load_stix_json(const std::string& provided_path) {
    std::filesystem::path selected_path;
    for (const auto& candidate : candidate_paths(provided_path)) {
        std::error_code error;
        if (std::filesystem::is_regular_file(candidate, error)) {
            selected_path = candidate;
            break;
        }
    }

    if (selected_path.empty()) {
        Logger::get_instance().log(LogLevel::WARN, "MITRE_STIX",
            "No MITRE ATT&CK STIX file found in configured search paths.");
        return false;
    }

    try {
        std::ifstream input(selected_path);
        if (!input.is_open()) {
            Logger::get_instance().log(LogLevel::ERR, "MITRE_STIX",
                "Unable to open MITRE STIX file: " + selected_path.string());
            return false;
        }

        nlohmann::json document;
        input >> document;
        if (!document.contains("objects") || !document["objects"].is_array()) {
            Logger::get_instance().log(LogLevel::ERR, "MITRE_STIX",
                "MITRE STIX document has no top-level objects array: " + selected_path.string());
            return false;
        }

        std::unordered_map<std::string, MitreTechniqueInfo> loaded;
        for (const auto& item : document["objects"]) {
            if (!item.is_object() || item.value("type", "") != "attack-pattern") continue;

            std::string external_id;
            if (item.contains("external_references") && item["external_references"].is_array()) {
                for (const auto& reference : item["external_references"]) {
                    if (!reference.is_object() || reference.value("source_name", "") != "mitre-attack") continue;
                    const auto id = reference.value("external_id", "");
                    if (!id.empty()) {
                        external_id = id;
                        break;
                    }
                }
            }
            if (external_id.empty()) continue;

            MitreTechniqueInfo technique;
            technique.id = external_id;
            technique.name = item.value("name", "");
            technique.description = item.value("description", "");

            if (item.contains("kill_chain_phases") && item["kill_chain_phases"].is_array()) {
                for (const auto& phase : item["kill_chain_phases"]) {
                    const auto phase_name = phase.value("phase_name", "");
                    if (!phase_name.empty()) technique.tactics.push_back(phase_name);
                }
            }

            if (item.contains("x_mitre_platforms") && item["x_mitre_platforms"].is_array()) {
                for (const auto& platform : item["x_mitre_platforms"]) {
                    if (platform.is_string()) technique.platforms.push_back(platform.get<std::string>());
                }
            }

            loaded[external_id] = std::move(technique);
        }

        {
            std::lock_guard<std::mutex> lock(stix_mutex_);
            techniques_ = std::move(loaded);
        }

        return true;
    } catch (const std::exception& exception) {
        Logger::get_instance().log(LogLevel::ERR, "MITRE_STIX",
            "Failed to parse MITRE STIX file " + selected_path.string() + ": " + exception.what());
        return false;
    }
}

MitreTechniqueInfo MitreEngine::lookup_technique(const std::string& technique_id) const {
    std::lock_guard<std::mutex> lock(stix_mutex_);
    const auto entry = techniques_.find(technique_id);
    return entry == techniques_.end() ? MitreTechniqueInfo{} : entry->second;
}

} // namespace copsec