#pragma once

#include <cstdint>
#include <mutex>
#include <string>

namespace copsec {

class SiemExporter {
public:
    struct Settings {
        bool enabled = false;
        std::string host = "127.0.0.1";
        std::uint16_t port = 514;
        std::string format = "cef";
        std::string logfile = "/var/log/copsec/siem_cef.log";
    };

    static SiemExporter& instance();
    void configure(Settings settings);
    void export_event(const std::string& event_id, const std::string& description,
                      int severity, const std::string& ip, const std::string& action,
                      const std::string& details);

private:
    SiemExporter() = default;
    std::string cef_escape(const std::string& value) const;
    mutable std::mutex mutex_;
    Settings settings_;
};

} // namespace copsec
