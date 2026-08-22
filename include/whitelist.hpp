#ifndef WHITELIST_HPP
#define WHITELIST_HPP

#include <string>
#include <vector>
#include <arpa/inet.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <cstring>
#include <algorithm>

class WhitelistManager {
private:
    struct IPv4CIDR {
        uint32_t ip;
        uint32_t mask;
    };

    struct IPv6CIDR {
        in6_addr ip;
        int prefix;
    };

    std::vector<IPv4CIDR> allowed_ipv4;
    std::vector<IPv6CIDR> allowed_ipv6;

    static uint32_t ip_to_int(const std::string& ip_str) {
        in_addr addr{};
        if (inet_pton(AF_INET, ip_str.c_str(), &addr) == 1) {
            return ntohl(addr.s_addr);
        }
        return 0;
    }

    static bool match_ipv6(const in6_addr& addr, const in6_addr& net, int prefix) {
        if (prefix < 0 || prefix > 128) return false;
        const int full_bytes = prefix / 8;
        const int rem_bits = prefix % 8;
        if (full_bytes > 0 && std::memcmp(&addr.s6_addr, &net.s6_addr, full_bytes) != 0) {
            return false;
        }
        if (rem_bits > 0) {
            const uint8_t mask = static_cast<uint8_t>(~0U << (8 - rem_bits));
            if ((addr.s6_addr[full_bytes] & mask) != (net.s6_addr[full_bytes] & mask)) {
                return false;
            }
        }
        return true;
    }

public:
    WhitelistManager() = default;

    static bool is_fast_path_builtin(const std::string& ip_str) {
        if (ip_str.empty()) return true;
        if (ip_str == "127.0.0.1" || ip_str == "::1" || ip_str == "localhost" ||
            ip_str == "::ffff:127.0.0.1" || ip_str == "0:0:0:0:0:0:0:1") {
            return true;
        }

        // Check IPv4 ranges
        in_addr addr4{};
        if (inet_pton(AF_INET, ip_str.c_str(), &addr4) == 1) {
            const uint32_t ip = ntohl(addr4.s_addr);
            // 127.0.0.0/8 (0x7F000000)
            if ((ip & 0xFF000000U) == 0x7F000000U) return true;
            // 100.64.0.0/10 (Tailscale CGNAT: 0x64400000, mask 0xFFC00000)
            if ((ip & 0xFFC00000U) == 0x64400000U) return true;
            return false;
        }

        // Check IPv6 loopback ::1/128
        in6_addr addr6{};
        if (inet_pton(AF_INET6, ip_str.c_str(), &addr6) == 1) {
            static const in6_addr loopback_addr = IN6ADDR_LOOPBACK_INIT;
            if (std::memcmp(&addr6, &loopback_addr, sizeof(in6_addr)) == 0) {
                return true;
            }
            // IPv4-mapped IPv6 loopback ::ffff:127.0.0.0/104 or ::ffff:100.64.0.0/106
            if (IN6_IS_ADDR_V4MAPPED(&addr6)) {
                const uint32_t mapped_ip = ntohl(*reinterpret_cast<const uint32_t*>(&addr6.s6_addr[12]));
                if ((mapped_ip & 0xFF000000U) == 0x7F000000U) return true;
                if ((mapped_ip & 0xFFC00000U) == 0x64400000U) return true;
            }
            return false;
        }

        return false;
    }

    bool load_whitelist(const std::string& config_path) {
        std::ifstream file(config_path);
        if (!file.is_open()) return false;

        try {
            nlohmann::json j;
            file >> j;
            allowed_ipv4.clear();
            allowed_ipv6.clear();

            if (j.contains("trusted_cidrs") && j["trusted_cidrs"].is_array()) {
                for (const auto& item : j["trusted_cidrs"]) {
                    if (!item.is_string()) continue;
                    std::string cidr_str = item.get<std::string>();
                    std::size_t slash = cidr_str.find('/');

                    std::string ip_part = (slash != std::string::npos) ? cidr_str.substr(0, slash) : cidr_str;
                    int prefix = (slash != std::string::npos) ? std::stoi(cidr_str.substr(slash + 1)) : -1;

                    in_addr addr4{};
                    if (inet_pton(AF_INET, ip_part.c_str(), &addr4) == 1) {
                        if (prefix < 0) prefix = 32;
                        prefix = std::clamp(prefix, 0, 32);
                        uint32_t ip = ntohl(addr4.s_addr);
                        uint32_t mask = (prefix == 0) ? 0 : (~0U << (32 - prefix));
                        allowed_ipv4.push_back({ip, mask});
                        continue;
                    }

                    in6_addr addr6{};
                    if (inet_pton(AF_INET6, ip_part.c_str(), &addr6) == 1) {
                        if (prefix < 0) prefix = 128;
                        prefix = std::clamp(prefix, 0, 128);
                        allowed_ipv6.push_back({addr6, prefix});
                        continue;
                    }
                }
            }
            return true;
        } catch (...) {
            return false;
        }
    }

    bool is_whitelisted(const std::string& ip_str) const {
        if (is_fast_path_builtin(ip_str)) return true;

        in_addr addr4{};
        if (inet_pton(AF_INET, ip_str.c_str(), &addr4) == 1) {
            const uint32_t target = ntohl(addr4.s_addr);
            for (const auto& net : allowed_ipv4) {
                if ((target & net.mask) == (net.ip & net.mask)) {
                    return true;
                }
            }
            return false;
        }

        in6_addr addr6{};
        if (inet_pton(AF_INET6, ip_str.c_str(), &addr6) == 1) {
            for (const auto& net : allowed_ipv6) {
                if (match_ipv6(addr6, net.ip, net.prefix)) {
                    return true;
                }
            }
            return false;
        }

        return false;
    }
};

#endif // WHITELIST_HPP