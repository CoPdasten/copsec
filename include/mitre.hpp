#pragma once

#include <string>
#include <unordered_map>
#include <nlohmann/json.hpp>

namespace copsec {

struct MitreMetadata {
    std::string tactic;
    std::string tactic_id;
    std::string technique_id;
    std::string technique_name;
    std::string url;
};

class MitreMapper {
public:
    static MitreMapper& get_instance();

    // Disable copy/move
    MitreMapper(const MitreMapper&) = delete;
    MitreMapper& operator=(const MitreMapper&) = delete;
    MitreMapper(MitreMapper&&) = delete;
    MitreMapper& operator=(MitreMapper&&) = delete;

    // Registers metadata mapping for a rule
    void register_metadata(const std::string& rule_id, const MitreMetadata& meta);

    // Retrieves MITRE ATT&CK metadata for a given rule ID
    MitreMetadata get_metadata(const std::string& rule_id) const;

    // Loads mappings from rules.json
    bool load_from_rules_json(const nlohmann::json& rules_json);

private:
    MitreMapper() = default;
    ~MitreMapper() = default;

    std::unordered_map<std::string, MitreMetadata> m_mappings;
};

} // namespace copsec
