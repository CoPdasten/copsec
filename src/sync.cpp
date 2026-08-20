#include <curl/curl.h>
#include <nlohmann/json.hpp>

void push_to_central_api(const std::string& ip, const std::string& rule_id) {
    CURL* curl = curl_easy_init();
    if (curl) {
        nlohmann::json j = {
            {"agent_id", "parrot-agent-01"},
            {"ip", ip},
            {"rule_id", rule_id}
        };
        std::string data = j.dump();

        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8080/api/v1/telemetry/push");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L); // Non-blocking hızlı zaman aşımı

        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
}