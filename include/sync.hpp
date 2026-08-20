#ifndef SYNC_HPP
#define SYNC_HPP

#include <string>
#include <vector>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

namespace copsec {

class SyncModule {
public:
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        ((std::string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    }

    static void push_telemetry(const std::string& server_url, const std::string& agent_id, const std::string& ip, const std::string& rule_id) {
        CURL* curl = curl_easy_init();
        if (curl) {
            nlohmann::json payload = {
                {"agent_id", agent_id},
                {"ip", ip},
                {"rule_id", rule_id}
            };
            std::string data = payload.dump();

            struct curl_slist* headers = NULL;
            headers = curl_slist_append(headers, "Content-Type: application/json");

            curl_easy_setopt(curl, CURLOPT_URL, server_url.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L);

            curl_easy_perform(curl);
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
        }
    }

    static std::vector<std::string> pull_global_blocklist(const std::string& server_url) {
        std::vector<std::string> blocklist;
        CURL* curl = curl_easy_init();
        if (curl) {
            std::string readBuffer;
            curl_easy_setopt(curl, CURLOPT_URL, server_url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3L);

            CURLcode res = curl_easy_perform(curl);
            curl_easy_cleanup(curl);

            if (res == CURLE_OK) {
                try {
                    auto j = nlohmann::json::parse(readBuffer);
                    if (j.contains("blocklist") && j["blocklist"].is_array()) {
                        for (const auto& item : j["blocklist"]) {
                            blocklist.push_back(item.get<std::string>());
                        }
                    }
                } catch (...) {}
            }
        }
        return blocklist;
    }
};

} // namespace copsec

#endif // SYNC_HPP