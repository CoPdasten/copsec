#pragma once

#include <string>
#include <vector>

namespace copsec {

class PenaltyEngine;
class ShmServer;

class DecoyEngine {
public:
    struct Settings {
        bool enabled = true;
        std::vector<std::string> paths;
    };

    DecoyEngine(PenaltyEngine& penalty_engine, ShmServer& shm_server, Settings settings);
    bool inspect_request(const std::string& ip, const std::string& request_path);
    bool inspect(const std::string& ip, const std::string& request_line);
    bool matches(const std::string& request_path, std::string& matched_path) const;

private:
    static const std::vector<std::string>& default_paths();
    PenaltyEngine& penalty_engine_;
    ShmServer& shm_server_;
    Settings settings_;
};

} // namespace copsec
