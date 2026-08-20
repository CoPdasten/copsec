#include "soar_worker.hpp"

#include "bouncer.hpp"
#include "logger.hpp"

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <arpa/inet.h>
#include <algorithm>
#include <cstdlib>
#include <sstream>

namespace copsec {
namespace {

size_t write_body(char* data, size_t size, size_t count, void* user_data) {
    auto* body = static_cast<std::string*>(user_data);
    body->append(data, size * count);
    return size * count;
}

bool valid_ipv4(const std::string& value) {
    in_addr address{};
    return inet_pton(AF_INET, value.c_str(), &address) == 1;
}

} // namespace

SoarWorker::SoarWorker(Bouncer& bouncer) : SoarWorker(bouncer, Settings{}) {}

SoarWorker::SoarWorker(Bouncer& bouncer, Settings settings)
    : bouncer_(bouncer), settings_(std::move(settings)) {}

SoarWorker::~SoarWorker() { stop(); }

bool SoarWorker::start() {
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true)) return false;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    next_refresh_ = std::chrono::steady_clock::now();
    thread_ = std::thread(&SoarWorker::run, this);
    return true;
}

void SoarWorker::stop() {
    if (!running_.exchange(false)) return;
    condition_.notify_all();
    if (thread_.joinable()) thread_.join();
    curl_global_cleanup();
}

void SoarWorker::on_ban_decision(std::string ip, int duration_seconds, std::string rule_id) {
    if (ip.empty() || !valid_ipv4(ip)) return;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push({std::move(ip), duration_seconds, std::move(rule_id)});
    }
    condition_.notify_one();
}

void SoarWorker::run() {
    while (running_) {
        BanRequest request;
        bool have_request = false;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            condition_.wait_until(lock, next_refresh_, [this] { return !running_ || !queue_.empty(); });
            if (!running_) break;
            if (!queue_.empty()) {
                request = std::move(queue_.front());
                queue_.pop();
                have_request = true;
            }
        }
        if (have_request) process_ban(request);
        if (std::chrono::steady_clock::now() >= next_refresh_) {
            refresh_lists();
            next_refresh_ = std::chrono::steady_clock::now() + settings_.refresh_period;
        }
    }
}

void SoarWorker::process_ban(const BanRequest& request) {
    const int score = abuse_confidence(request.ip);
    const int duration = score >= 80 ? 30 * 24 * 60 * 60 : request.duration_seconds;
    if (score >= 80) {
        Logger::get_instance().log(LogLevel::WARN, "ABUSEIPDB_ESCALATION",
            "AbuseIPDB confidence " + std::to_string(score) + "% for " + request.ip + "; escalating ban.");
    }
    if (duration != request.duration_seconds) {
        bouncer_.ban_ip(request.ip, duration, "abuseipdb_escalation");
    }
}

void SoarWorker::refresh_lists() {
    std::vector<std::string> indicators;
    for (const auto& url : {settings_.tor_exit_url, settings_.c2_url}) {
        const auto body = fetch(url);
        const auto parsed = parse_ip_list(body);
        indicators.insert(indicators.end(), parsed.begin(), parsed.end());
    }
    std::sort(indicators.begin(), indicators.end());
    indicators.erase(std::unique(indicators.begin(), indicators.end()), indicators.end());
    if (!indicators.empty()) {
        bouncer_.bulk_ban_ips(indicators, 12 * 60 * 60, "threat_intelligence");
        Logger::get_instance().log(LogLevel::INFO, "THREAT_INTEL_REFRESH",
            "Loaded " + std::to_string(indicators.size()) + " indicators into ban_list.");
    }
}

std::string SoarWorker::fetch(const std::string& url, const std::vector<std::string>& headers) const {
    CURL* curl = curl_easy_init();
    if (!curl) return {};
    std::string body;
    curl_slist* header_list = nullptr;
    for (const auto& header : headers) header_list = curl_slist_append(header_list, header.c_str());
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, settings_.request_timeout.count());
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    const CURLcode result = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(header_list);
    curl_easy_cleanup(curl);
    return result == CURLE_OK && status >= 200 && status < 300 ? body : std::string{};
}

int SoarWorker::abuse_confidence(const std::string& ip) const {
    const char* key = std::getenv("COPSEC_ABUSEIPDB_API_KEY");
    if (!key || *key == '\0') return 0;
    const auto body = fetch(settings_.abuse_api_url + "?ipAddress=" + ip + "&maxAgeInDays=90",
        {"Accept: application/json", std::string("Key: ") + key});
    try {
        const auto json = nlohmann::json::parse(body);
        return json.at("data").value("abuseConfidenceScore", 0);
    } catch (...) {
        return 0;
    }
}

std::vector<std::string> SoarWorker::parse_ip_list(const std::string& body) {
    std::vector<std::string> result;
    std::istringstream stream(body);
    std::string line;
    while (std::getline(stream, line)) {
        const auto comment = line.find('#');
        if (comment != std::string::npos) line.resize(comment);
        std::istringstream tokens(line);
        std::string token;
        while (tokens >> token) {
            if (valid_ipv4(token)) {
                result.push_back(token);
                break;
            }
        }
    }
    return result;
}

} // namespace copsec