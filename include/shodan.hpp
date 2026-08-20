#pragma once

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace copsec {

struct ShodanHostInfo {
    std::string country_name = "unknown";
    std::string city = "unknown";
    std::string isp = "unknown";
    std::string org = "unknown";
    std::vector<int> ports;
    std::vector<std::string> cves;
};

class ShodanClient {
public:
    explicit ShodanClient(std::string api_key = "CGxFnM5bpHAOKUXHNVrGHxaECIZB7CWj")
        : m_api_key(std::move(api_key)) {}

    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        auto* buffer = static_cast<std::string*>(userp);
        const size_t total = size * nmemb;
        buffer->append(static_cast<char*>(contents), total);
        return total;
    }

    ShodanHostInfo lookup_host(const std::string& ip_address) const {
        ShodanHostInfo info;
        if (ip_address.empty()) {
            return info;
        }

        CURL* curl = curl_easy_init();
        if (!curl) {
            return info;
        }

        std::string url = "https://api.shodan.io/shodan/host/" + ip_address + "?key=" + m_api_key;
        std::string response;

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "CoPSeC-Agent/1.0");

        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK || response.empty()) {
            return info;
        }

        try {
            const nlohmann::json data = nlohmann::json::parse(response);

            if (data.contains("country_name")) {
                info.country_name = data["country_name"].get<std::string>();
            }
            if (data.contains("city")) {
                info.city = data["city"].get<std::string>();
            }
            if (data.contains("isp")) {
                info.isp = data["isp"].get<std::string>();
            }
            if (data.contains("org")) {
                info.org = data["org"].get<std::string>();
            }
            if (data.contains("ports") && data["ports"].is_array()) {
                for (const auto& item : data["ports"]) {
                    if (item.is_number_integer()) {
                        info.ports.push_back(item.get<int>());
                    }
                }
            }
            if (data.contains("vulns") && data["vulns"].is_object()) {
                for (const auto& [key, value] : data["vulns"].items()) {
                    (void)value;
                    info.cves.push_back(key);
                }
            }

            if (info.country_name.empty()) {
                info.country_name = "unknown";
            }
            if (info.city.empty()) {
                info.city = "unknown";
            }
            if (info.isp.empty()) {
                info.isp = "unknown";
            }
            if (info.org.empty()) {
                info.org = "unknown";
            }
        } catch (const std::exception&) {
            return info;
        }

        return info;
    }

private:
    std::string m_api_key;
};

} // namespace copsec
