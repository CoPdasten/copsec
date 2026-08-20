#include "anti_evasion.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <vector>

namespace {

bool read_u16(const std::string& data, std::size_t& offset, std::uint16_t& value) {
    if (offset + 2 > data.size()) return false;
    value = (static_cast<std::uint8_t>(data[offset]) << 8) | static_cast<std::uint8_t>(data[offset + 1]);
    offset += 2;
    return true;
}

std::string join_values(const std::vector<std::uint16_t>& values) {
    std::ostringstream output;
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i) output << '-';
        output << values[i];
    }
    return output.str();
}

} // namespace

namespace copsec {

AntiEvasion::AntiEvasion(BanCallback ban_callback) : ban_callback_(std::move(ban_callback)) {
    if (const char* configured = std::getenv("COPSEC_MALICIOUS_FINGERPRINTS")) {
        std::istringstream values(configured);
        std::string value;
        while (std::getline(values, value, ',')) {
            if (!value.empty()) malicious_hashes_.insert(value);
        }
    }
}

bool AntiEvasion::allow_request(const std::string& source_ip, const std::string& user_agent) {
    const auto subnet24 = subnet_key(source_ip);
    const auto first_dot = subnet24.find('.');
    const auto second_dot = first_dot == std::string::npos ? std::string::npos : subnet24.find('.', first_dot + 1);
    const auto subnet16 = second_dot == std::string::npos ? subnet24 : subnet24.substr(0, second_dot);
    return consume(subnet24 + "|" + user_agent) && consume(subnet16);
}

FingerprintDecision AntiEvasion::inspect_tls_client_hello(const std::string& source_ip, const std::string& client_hello) {
    FingerprintDecision decision;
    decision.ja3 = ja3_digest(client_hello);
    decision.ja4 = ja4_digest(client_hello);
    evaluate(source_ip, decision);
    return decision;
}

FingerprintDecision AntiEvasion::inspect_http_headers(const std::string& source_ip, const std::string& headers) {
    FingerprintDecision decision;
    decision.header_fingerprint = header_digest(headers);
    evaluate(source_ip, decision);
    return decision;
}

void AntiEvasion::add_malicious_fingerprint(std::string hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    malicious_hashes_.insert(std::move(hash));
}

bool AntiEvasion::consume(const std::string& key) {
    constexpr double capacity = 20.0;
    constexpr double leak_per_second = 0.5;
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mutex_);
    auto& bucket = buckets_[key];
    if (bucket.updated.time_since_epoch().count() == 0) bucket.updated = now;
    const double elapsed = std::chrono::duration<double>(now - bucket.updated).count();
    bucket.level = std::max(0.0, bucket.level - elapsed * leak_per_second);
    bucket.updated = now;
    if (bucket.level + 1.0 > capacity) return false;
    bucket.level += 1.0;
    return true;
}

std::string AntiEvasion::digest(const std::string& value) {
    unsigned char output[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    EVP_Digest(value.data(), value.size(), output, &length, EVP_sha256(), nullptr);
    std::ostringstream result;
    result << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < length; ++i) result << std::setw(2) << static_cast<unsigned>(output[i]);
    return result.str();
}

std::string AntiEvasion::subnet_key(const std::string& ip) {
    const auto last_dot = ip.rfind('.');
    return last_dot == std::string::npos ? ip : ip.substr(0, last_dot);
}

std::string AntiEvasion::header_digest(const std::string& headers) {
    std::string normalized;
    std::istringstream input(headers);
    std::string line;
    while (std::getline(input, line)) {
        std::transform(line.begin(), line.end(), line.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        const auto colon = line.find(':');
        if (colon != std::string::npos) normalized += line.substr(0, colon) + ":" + line.substr(colon + 1) + "\n";
    }
    return digest(normalized);
}

std::string AntiEvasion::ja3_digest(const std::string& client_hello) {
    std::size_t offset = 0;
    if (client_hello.size() >= 5 && static_cast<unsigned char>(client_hello[0]) == 22) offset = 5;
    if (offset + 4 > client_hello.size() || static_cast<unsigned char>(client_hello[offset]) != 1) return digest("ja3:" + client_hello);
    offset += 4;
    std::uint16_t version = 0, length = 0;
    if (!read_u16(client_hello, offset, version) || offset + 32 > client_hello.size()) return digest("ja3:" + client_hello);
    offset += 32;
    if (offset >= client_hello.size()) return digest("ja3:" + client_hello);
    const auto session_length = static_cast<unsigned char>(client_hello[offset++]);
    if (offset + session_length > client_hello.size() || !read_u16(client_hello, offset, length) || offset + length > client_hello.size()) return digest("ja3:" + client_hello);
    std::vector<std::uint16_t> ciphers;
    for (std::size_t end = offset + length; offset + 1 < end; offset += 2) ciphers.push_back((static_cast<unsigned char>(client_hello[offset]) << 8) | static_cast<unsigned char>(client_hello[offset + 1]));
    if (offset >= client_hello.size()) return digest("ja3:" + client_hello);
    const auto compression_length = static_cast<unsigned char>(client_hello[offset++]);
    if (offset + compression_length > client_hello.size()) return digest("ja3:" + client_hello);
    offset += compression_length;
    std::vector<std::uint16_t> extensions;
    std::vector<std::uint16_t> curves;
    std::vector<std::uint16_t> formats;
    if (offset + 2 <= client_hello.size() && read_u16(client_hello, offset, length) && offset + length <= client_hello.size()) {
        const auto extensions_end = offset + length;
        while (offset + 4 <= extensions_end) {
            std::uint16_t type = 0, size = 0;
            read_u16(client_hello, offset, type);
            read_u16(client_hello, offset, size);
            if (offset + size > extensions_end) break;
            extensions.push_back(type);
            if (type == 10 && size >= 2) {
                std::size_t nested = offset;
                std::uint16_t curve_size = 0;
                read_u16(client_hello, nested, curve_size);
                for (std::size_t end = std::min(offset + size, nested + curve_size); nested + 1 < end; nested += 2) curves.push_back((static_cast<unsigned char>(client_hello[nested]) << 8) | static_cast<unsigned char>(client_hello[nested + 1]));
            } else if (type == 11 && size >= 1) {
                std::size_t nested = offset + 1;
                const auto format_size = static_cast<unsigned char>(client_hello[offset]);
                for (std::size_t end = std::min(offset + size, nested + format_size); nested < end; ++nested) formats.push_back(static_cast<unsigned char>(client_hello[nested]));
            }
            offset += size;
        }
    }
    const auto ja3 = std::to_string(version) + "," + join_values(ciphers) + "," + join_values(extensions) + "," + join_values(curves) + "," + join_values(formats);
    unsigned char output[EVP_MAX_MD_SIZE];
    unsigned int output_size = 0;
    EVP_Digest(ja3.data(), ja3.size(), output, &output_size, EVP_md5(), nullptr);
    std::ostringstream result;
    result << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < output_size; ++i) result << std::setw(2) << static_cast<unsigned>(output[i]);
    return result.str();
}

std::string AntiEvasion::ja4_digest(const std::string& client_hello) {
    return digest("ja4:" + ja3_digest(client_hello) + ":" + std::to_string(client_hello.size()));
}

void AntiEvasion::evaluate(const std::string& source_ip, FingerprintDecision& decision) {
    bool blocked = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked = malicious_hashes_.find(decision.ja3) != malicious_hashes_.end() ||
              malicious_hashes_.find(decision.ja4) != malicious_hashes_.end() ||
              malicious_hashes_.find(decision.header_fingerprint) != malicious_hashes_.end();
    }
    decision.allowed = !blocked;
    if (blocked && ban_callback_) ban_callback_(source_ip, 2 * 24 * 60 * 60, "malicious_fingerprint");
}

} // namespace copsec