#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace copsec {

struct FingerprintDecision {
    bool allowed = true;
    std::string ja3;
    std::string ja4;
    std::string header_fingerprint;
};

class AntiEvasion {
public:
    using BanCallback = std::function<void(const std::string&, int, const std::string&)>;

    explicit AntiEvasion(BanCallback ban_callback);
    bool allow_request(const std::string& source_ip, const std::string& user_agent = {});
    FingerprintDecision inspect_tls_client_hello(const std::string& source_ip, const std::string& client_hello);
    FingerprintDecision inspect_http_headers(const std::string& source_ip, const std::string& headers);
    void add_malicious_fingerprint(std::string hash);

private:
    struct Bucket { double level = 0.0; std::chrono::steady_clock::time_point updated; };
    bool consume(const std::string& key);
    static std::string digest(const std::string& value);
    static std::string subnet_key(const std::string& ip);
    static std::string header_digest(const std::string& headers);
    static std::string ja3_digest(const std::string& client_hello);
    static std::string ja4_digest(const std::string& client_hello);
    void evaluate(const std::string& source_ip, FingerprintDecision& decision);

    BanCallback ban_callback_;
    std::mutex mutex_;
    std::unordered_map<std::string, Bucket> buckets_;
    std::unordered_set<std::string> malicious_hashes_;
};

} // namespace copsec