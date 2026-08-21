#include "mitre.hpp"
#include "logger.hpp"

namespace copsec {

MitreMapper& MitreMapper::get_instance() {
    static MitreMapper instance;
    return instance;
}

void MitreMapper::register_metadata(const std::string& rule_id, const MitreMetadata& meta) {
    m_mappings[rule_id].mappings.push_back(meta);
}

MitreMetadata MitreMapper::get_metadata(const std::string& rule_id) const {
    auto it = m_mappings.find(rule_id);
    if (it != m_mappings.end() && !it->second.mappings.empty()) {
        return it->second.mappings.front();
    }
    return MitreMetadata{ "Unknown Tactic", "Unknown Tactic ID", "Unknown Technique ID", "Unknown Technique Name", "" };
}

std::vector<MitreMetadata> MitreMapper::get_metadata_all(const std::string& rule_id) const {
    const auto it = m_mappings.find(rule_id);
    return it == m_mappings.end() ? std::vector<MitreMetadata>{} : it->second.mappings;
}

bool MitreMapper::load_from_rules_json(const nlohmann::json& rules_json) {
    try {
        if (!rules_json.contains("rules") || !rules_json["rules"].is_array()) {
            Logger::get_instance().log(LogLevel::ERR, "CONFIG_ERROR", "rules.json is missing 'rules' array");
            return false;
        }

        for (const auto& rule : rules_json["rules"]) {
            std::string rule_id = rule.value("id", "");
            if (rule_id.empty()) continue;

            if (rule.contains("mitre") && rule["mitre"].is_array()) {
                for (const auto& item : rule["mitre"]) {
                    register_metadata(rule_id, MitreMetadata{
                        item.value("tactic", ""), item.value("tactic_id", ""),
                        item.value("technique_id", ""), item.value("technique_name", ""),
                        item.value("url", "")});
                }
                continue;
            }

            if (rule.contains("mitre_tactic") || rule.contains("mitre_technique")) {
                MitreMetadata meta;
                meta.tactic = rule.value("mitre_tactic", "");
                meta.tactic_id = rule.value("mitre_tactic_id", "");
                meta.technique_id = rule.value("mitre_technique", "");
                meta.technique_name = rule.value("mitre_technique_name", "");
                meta.url = rule.value("mitre_url", "");
                register_metadata(rule_id, meta);
                Logger::get_instance().log(LogLevel::INFO, "MITRE_LOADED",
                    "Loaded MITRE ATT&CK mapping for rule: " + rule_id + " (" + meta.technique_id + ")");
            } else if (rule.contains("mitre")) {
                auto mitre = rule["mitre"];
                MitreMetadata meta;
                meta.tactic = mitre.value("tactic", "");
                meta.tactic_id = mitre.value("tactic_id", "");
                meta.technique_id = mitre.value("technique_id", "");
                meta.technique_name = mitre.value("technique_name", "");
                meta.url = mitre.value("url", "");

                register_metadata(rule_id, meta);
                Logger::get_instance().log(LogLevel::INFO, "MITRE_LOADED", 
                    "Loaded MITRE ATT&CK mapping for rule: " + rule_id + " (" + meta.technique_id + ")");
            }
        }
        return true;
    } catch (const std::exception& e) {
        Logger::get_instance().log(LogLevel::ERR, "CONFIG_ERROR", 
            std::string("Exception parsing MITRE metadata: ") + e.what());
        return false;
    }
}

} // namespace copsec
