#pragma once

#include <algorithm>
#include <string>
#include <vector>

namespace copsec {

class HoneypotEngine {
public:
    static const std::vector<std::string>& decoy_endpoints() {
        static const std::vector<std::string> endpoints = {
            "/.env",
            "/wp-login.php",
            "/config.php",
            "/.git/config",
            "/actuator/health",
            "/phpmyadmin/index.php",
            "/.aws/credentials"
        };
        return endpoints;
    }

    bool is_honeypot_hit(const std::string& normalized_line, std::string& matched_trap) const {
        matched_trap.clear();
        if (normalized_line.empty()) {
            return false;
        }

        std::string lower = normalized_line;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });

        for (const auto& trap : decoy_endpoints()) {
            std::string lower_trap = trap;
            std::transform(lower_trap.begin(), lower_trap.end(), lower_trap.begin(), [](unsigned char ch) {
                return static_cast<char>(std::tolower(ch));
            });

            if (lower.find(lower_trap) != std::string::npos) {
                matched_trap = trap;
                return true;
            }
        }

        return false;
    }
};

} // namespace copsec
