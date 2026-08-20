#pragma once

#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace copsec {

struct TechniqueProfile {
    std::string id;
    std::string name;
    std::string description;
    std::vector<std::string> tactics;
    std::vector<std::string> mitigations;
    std::vector<std::string> actors;
    std::vector<std::string> aliases;
};

struct ThreatActorProfile {
    std::string id;
    std::string name;
    std::string description;
    std::vector<std::string> aliases;
    std::vector<std::string> techniques;
};

class StixParser {
public:
    StixParser() = default;

    bool load_file(const std::string& path) {
        std::ifstream input(path);
        if (!input.is_open()) {
            return false;
        }
        try {
            nlohmann::json root;
            input >> root;
            return load_json(root);
        } catch (const std::exception&) {
            return false;
        }
    }

    bool load_json(const nlohmann::json& root) {
        techniques_.clear();
        actors_.clear();
        mitigation_lookup_.clear();
        technique_to_actors_.clear();

        if (!root.is_object()) {
            return false;
        }

        if (root.contains("objects") && root["objects"].is_array()) {
            return parse_stix_objects(root["objects"]);
        }

        if (root.contains("techniques") && root["techniques"].is_object()) {
            return parse_local_mapping(root["techniques"]);
        }

        return false;
    }

    TechniqueProfile query_technique(const std::string& technique_id) const {
        TechniqueProfile profile;
        auto it = techniques_.find(technique_id);
        if (it != techniques_.end()) {
            return it->second;
        }

        std::string normalized = normalize_identifier(technique_id);
        auto alt = techniques_.find(normalized);
        if (alt != techniques_.end()) {
            return alt->second;
        }

        return profile;
    }

    std::vector<std::string> mitigations_for(const std::string& technique_id) const {
        std::vector<std::string> result;
        auto it = mitigation_lookup_.find(normalize_identifier(technique_id));
        if (it != mitigation_lookup_.end()) {
            result = it->second;
        }
        return result;
    }

    std::vector<ThreatActorProfile> actors_for(const std::string& technique_id) const {
        std::vector<ThreatActorProfile> result;
        const std::string normalized = normalize_identifier(technique_id);
        auto it = technique_to_actors_.find(normalized);
        if (it == technique_to_actors_.end()) {
            return result;
        }

        for (const auto& actor_id : it->second) {
            auto actor_it = actors_.find(actor_id);
            if (actor_it != actors_.end()) {
                result.push_back(actor_it->second);
            }
        }
        return result;
    }

    bool load_default_offline_dataset() {
        std::vector<std::string> candidates = {
            "config/mitre_db.json",
            "../config/mitre_db.json",
            "./mitre_db.json",
            "/etc/copsec/mitre_db.json"
        };

        for (const auto& candidate : candidates) {
            if (std::filesystem::exists(candidate)) {
                return load_file(candidate);
            }
        }

        return false;
    }

private:
    bool parse_stix_objects(const nlohmann::json& objects) {
        std::unordered_map<std::string, std::vector<std::string>> relationship_map;
        std::unordered_map<std::string, std::vector<std::string>> technique_to_mitigations;
        std::unordered_map<std::string, std::vector<std::string>> technique_to_actors;

        for (const auto& entry : objects) {
            if (!entry.is_object()) {
                continue;
            }

            const std::string type = entry.value("type", "");
            const std::string id = entry.value("id", "");
            if (type == "attack-pattern") {
                const std::string technique_id = entry.value("external_references", nlohmann::json::array()).size() > 0
                    ? extract_external_id(entry["external_references"]) : normalize_identifier(id);

                TechniqueProfile profile;
                profile.id = technique_id;
                profile.name = entry.value("name", "");
                profile.description = entry.value("description", "Unknown description");
                if (entry.contains("kill_chain_phases") && entry["kill_chain_phases"].is_array()) {
                    for (const auto& phase : entry["kill_chain_phases"]) {
                        if (phase.contains("phase_name")) {
                            profile.tactics.push_back(phase["phase_name"].get<std::string>());
                        }
                    }
                }
                techniques_[normalize_identifier(technique_id)] = profile;
            } else if (type == "course-of-action") {
                std::string name = entry.value("name", "");
                std::string id = entry.value("id", "");
                if (!id.empty()) {
                    mitigation_lookup_[normalize_identifier(id)] = {name};
                }
            } else if (type == "intrusion-set") {
                ThreatActorProfile actor;
                actor.id = entry.value("id", "");
                actor.name = entry.value("name", "");
                actor.description = entry.value("description", "");
                if (entry.contains("aliases") && entry["aliases"].is_array()) {
                    for (const auto& alias : entry["aliases"]) {
                        actor.aliases.push_back(alias.get<std::string>());
                    }
                }
                actors_[normalize_identifier(actor.id)] = actor;
            } else if (type == "relationship") {
                const std::string source_ref = entry.value("source_ref", "");
                const std::string target_ref = entry.value("target_ref", "");
                const std::string relationship_type = entry.value("relationship_type", "");
                if (!source_ref.empty() && !target_ref.empty()) {
                    relationship_map[source_ref].push_back(target_ref);
                    if (relationship_type == "uses" || relationship_type == "mitigates" || relationship_type == "attributed-to") {
                        if (!source_ref.empty()) {
                            // stored for later resolution
                        }
                    }
                }
            }
        }

        for (const auto& entry : objects) {
            if (!entry.is_object()) {
                continue;
            }
            const std::string type = entry.value("type", "");
            if (type != "relationship") {
                continue;
            }

            const std::string relationship_type = entry.value("relationship_type", "");
            const std::string source_ref = entry.value("source_ref", "");
            const std::string target_ref = entry.value("target_ref", "");
            if (relationship_type == "uses") {
                const std::string actor_id = normalize_identifier(source_ref);
                const std::string technique_id = normalize_identifier(target_ref);
                if (!actor_id.empty() && !technique_id.empty()) {
                    technique_to_actors[technique_id].push_back(actor_id);
                }
            } else if (relationship_type == "mitigates") {
                const std::string tech_id = normalize_identifier(source_ref);
                const std::string mitigation_id = normalize_identifier(target_ref);
                if (!tech_id.empty() && !mitigation_id.empty()) {
                    technique_to_mitigations[tech_id].push_back(mitigation_id);
                }
            }
        }

        for (auto& [technique_id, profile] : techniques_) {
            auto mit_it = technique_to_mitigations.find(technique_id);
            if (mit_it != technique_to_mitigations.end()) {
                for (const auto& mitigation_id : mit_it->second) {
                    if (!mitigation_id.empty()) {
                        profile.mitigations.push_back(mitigation_id);
                    }
                }
            }
            auto actor_it = technique_to_actors.find(technique_id);
            if (actor_it != technique_to_actors.end()) {
                for (const auto& actor_id : actor_it->second) {
                    profile.actors.push_back(actor_id);
                }
            }
            techniques_[technique_id] = profile;
        }

        mitigation_lookup_ = technique_to_mitigations;
        technique_to_actors_ = technique_to_actors;
        return !techniques_.empty();
    }

    bool parse_local_mapping(const nlohmann::json& techniques) {
        for (auto it = techniques.begin(); it != techniques.end(); ++it) {
            const std::string technique_id = it.key();
            const auto& value = it.value();
            TechniqueProfile profile;
            profile.id = technique_id;
            profile.name = value.value("name", "");
            profile.description = value.value("description", "");
            profile.tactics.push_back(value.value("tactic", ""));

            if (value.contains("sub_techniques") && value["sub_techniques"].is_object()) {
                for (auto sub_it = value["sub_techniques"].begin(); sub_it != value["sub_techniques"].end(); ++sub_it) {
                    const std::string sub_id = sub_it.key();
                    const auto& sub_value = sub_it.value();
                    TechniqueProfile sub_profile;
                    sub_profile.id = sub_id;
                    sub_profile.name = sub_value.value("name", "");
                    sub_profile.description = sub_value.value("description", "");
                    sub_profile.mitigations = parse_mitigations(sub_value.value("mitigations", nlohmann::json::array()));
                    techniques_[normalize_identifier(sub_id)] = sub_profile;
                }
            }

            profile.mitigations = parse_mitigations(value.value("mitigations", nlohmann::json::array()));
            if (value.contains("sub_techniques") && value["sub_techniques"].is_object()) {
                for (auto sub_it = value["sub_techniques"].begin(); sub_it != value["sub_techniques"].end(); ++sub_it) {
                    auto& sub_profile = techniques_[normalize_identifier(sub_it.key())];
                    sub_profile.tactics.push_back(profile.tactics.empty() ? "" : profile.tactics.front());
                    sub_profile.mitigations = parse_mitigations(sub_it.value().value("mitigations", nlohmann::json::array()));
                    techniques_[normalize_identifier(sub_it.key())] = sub_profile;
                }
            }
            techniques_[normalize_identifier(technique_id)] = profile;
        }
        return !techniques_.empty();
    }

    static std::vector<std::string> parse_mitigations(const nlohmann::json& mitigations) {
        std::vector<std::string> result;
        if (!mitigations.is_array()) {
            return result;
        }
        for (const auto& mitigation : mitigations) {
            if (mitigation.is_string()) {
                result.push_back(mitigation.get<std::string>());
            }
        }
        return result;
    }

    static std::string normalize_identifier(const std::string& value) {
        std::string normalized = value;
        if (normalized.find("attack-pattern--") != std::string::npos) {
            return normalized;
        }
        if (normalized.rfind("T", 0) == 0 || normalized.rfind("M", 0) == 0 || normalized.rfind("G", 0) == 0) {
            return normalized;
        }
        std::string out = value;
        out.erase(std::remove(out.begin(), out.end(), ' '), out.end());
        return out;
    }

    static std::string extract_external_id(const nlohmann::json& refs) {
        if (!refs.is_array()) {
            return "";
        }
        for (const auto& ref : refs) {
            if (ref.is_object() && ref.contains("external_id")) {
                return ref["external_id"].get<std::string>();
            }
        }
        return "";
    }

    std::unordered_map<std::string, TechniqueProfile> techniques_;
    std::unordered_map<std::string, ThreatActorProfile> actors_;
    std::unordered_map<std::string, std::vector<std::string>> mitigation_lookup_;
    std::unordered_map<std::string, std::vector<std::string>> technique_to_actors_;
};

} // namespace copsec
