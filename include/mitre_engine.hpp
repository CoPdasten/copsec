#pragma once

#include "mitre.hpp"
#include "mitre_fetcher.hpp"

#include <mutex>
#include <string>
#include <unordered_map>

namespace copsec {

class MitreEngine {
public:
    bool initialize(const nlohmann::json& rules_json);
    MitreMetadata mapping_for(const std::string& rule_id) const;
    MitreMetadata get_technique(const std::string& rule_id) const;
    nlohmann::json enrich_event(const nlohmann::json& event) const;

    bool load_stix_json(const std::string& provided_path);
    bool refresh_from_taxii(const std::string& endpoint, const std::string& cache_path);
    MitreTechniqueInfo lookup_technique(const std::string& technique_id) const;

private:
    mutable std::mutex stix_mutex_;
    std::unordered_map<std::string, MitreTechniqueInfo> techniques_;
};

} // namespace copsec