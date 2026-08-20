#pragma once

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace copsec {

struct MitreTechniqueInfo {
    std::string id;
    std::string name;
    std::string description;
    std::vector<std::string> tactics;
    std::vector<std::string> sub_techniques;
    std::vector<std::string> mitigations;
    std::vector<std::string> platforms;
};

class MitreFetcher {
public:
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        auto* buffer = static_cast<std::string*>(userp);
        const size_t total = size * nmemb;
        buffer->append(static_cast<char*>(contents), total);
        return total;
    }

    static MitreTechniqueInfo fetch_technique(const std::string& technique_id) {
        static std::mutex cache_mutex;
        static std::map<std::string, MitreTechniqueInfo> cache;

        std::lock_guard<std::mutex> lock(cache_mutex);
        auto it = cache.find(technique_id);
        if (it != cache.end()) {
            return it->second;
        }

        MitreTechniqueInfo info;
        info.id = technique_id;

        std::vector<std::string> urls = {
            "https://attack.mitre.org/api/v2/techniques/" + technique_id + "/",
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/techniques/" + technique_id + ".json"
        };

        for (const auto& url : urls) {
            std::string response;
            CURL* curl = curl_easy_init();
            if (!curl) {
                continue;
            }

            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 6L);
            curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(curl, CURLOPT_USERAGENT, "CoPSeC-Agent/1.0");

            const CURLcode res = curl_easy_perform(curl);
            curl_easy_cleanup(curl);

            if (res != CURLE_OK || response.empty()) {
                continue;
            }

            try {
                const nlohmann::json data = nlohmann::json::parse(response);

                if (data.contains("name")) {
                    info.name = data["name"].get<std::string>();
                }
                if (data.contains("description")) {
                    info.description = data["description"].get<std::string>();
                }
                if (data.contains("kill_chain_phases") && data["kill_chain_phases"].is_array()) {
                    for (const auto& phase : data["kill_chain_phases"]) {
                        if (phase.contains("phase_name")) {
                            info.tactics.push_back(phase["phase_name"].get<std::string>());
                        }
                    }
                }
                if (data.contains("x_mitre_is_subtechnique") && data["x_mitre_is_subtechnique"].get<bool>()) {
                    info.sub_techniques.push_back(technique_id);
                }
                if (data.contains("external_references") && data["external_references"].is_array()) {
                    for (const auto& ref : data["external_references"]) {
                        if (ref.contains("external_id") && ref["external_id"].is_string()) {
                            const std::string ext = ref["external_id"].get<std::string>();
                            if (ext.rfind("M", 0) == 0) {
                                info.mitigations.push_back(ext);
                            }
                        }
                    }
                }
                if (data.contains("platforms") && data["platforms"].is_array()) {
                    for (const auto& platform : data["platforms"]) {
                        info.platforms.push_back(platform.get<std::string>());
                    }
                }
                if (data.contains("subtechniques") && data["subtechniques"].is_array()) {
                    for (const auto& sub : data["subtechniques"]) {
                        if (sub.is_string()) {
                            info.sub_techniques.push_back(sub.get<std::string>());
                        }
                    }
                }
                if (data.contains("mitigations") && data["mitigations"].is_array()) {
                    for (const auto& mitigation : data["mitigations"]) {
                        if (mitigation.contains("name")) {
                            info.mitigations.push_back(mitigation["name"].get<std::string>());
                        }
                    }
                }

                if (!info.name.empty() || !info.description.empty()) {
                    cache[technique_id] = info;
                    return info;
                }
            } catch (const std::exception&) {
                continue;
            }
        }

        cache[technique_id] = info;
        return info;
    }
};

} // namespace copsec
