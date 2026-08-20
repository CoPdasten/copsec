#ifndef WHITELIST_HPP
#define WHITELIST_HPP

#include <string>
#include <vector>
#include <arpa/inet.h>
#include <nlohmann/json.hpp>
#include <fstream>

class WhitelistManager {
private:
    struct CIDR {
        uint32_t ip;
        uint32_t mask;
    };
    std::vector<CIDR> allowed_networks;

    static uint32_t ip_to_int(const std::string& ip_str) {
        in_addr addr;
        if (inet_pton(AF_INET, ip_str.c_str(), &addr) == 1) {
            return ntohl(addr.s_addr);
        }
        return 0;
    }

public:
    bool load_whitelist(const std::string& config_path) {
        std::ifstream file(config_path);
        if (!file.is_open()) return false;

        try {
            nlohmann::json j;
            file >> j;
            allowed_networks.clear();

            for (const auto& item : j["trusted_cidrs"]) {
                std::string cidr_str = item.get<std::string>();
                std::size_t slash = cidr_str.find('/');
                
                std::string ip_part = (slash != std::string::npos) ? cidr_str.substr(0, slash) : cidr_str;
                int prefix = (slash != std::string::npos) ? std::stoi(cidr_str.substr(slash + 1)) : 32;

                uint32_t ip = ip_to_int(ip_part);
                uint32_t mask = (prefix == 0) ? 0 : (~0U << (32 - prefix));

                allowed_networks.push_back({ip, mask});
            }
            return true;
        } catch (...) {
            return false;
        }
    }

    bool is_whitelisted(const std::string& ip_str) const {
        uint32_t target_ip = ip_to_int(ip_str);
        if (target_ip == 0) return false;

        for (const auto& net : allowed_networks) {
            if ((target_ip & net.mask) == (net.ip & net.mask)) {
                return true;
            }
        }
        return false;
    }
};

#endif // WHITELIST_HPP