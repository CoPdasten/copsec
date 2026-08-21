#include "siem_exporter.hpp"

#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

namespace copsec {

SiemExporter& SiemExporter::instance() {
    static SiemExporter exporter;
    return exporter;
}

void SiemExporter::configure(Settings settings) {
    std::lock_guard<std::mutex> lock(mutex_);
    settings_ = std::move(settings);
}

std::string SiemExporter::cef_escape(const std::string& value) const {
    std::string escaped;
    escaped.reserve(value.size());
    for (const char character : value) {
        if (character == '\\' || character == '=' || character == '|') escaped.push_back('\\');
        escaped.push_back(character);
    }
    return escaped;
}

void SiemExporter::export_event(const std::string& event_id, const std::string& description,
                                int severity, const std::string& ip, const std::string& action,
                                const std::string& details) {
    Settings settings;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        settings = settings_;
    }
    if (!settings.enabled) return;

    const nlohmann::json json_event = {
        {"event_id", event_id}, {"description", description}, {"severity", severity},
        {"src", ip}, {"act", action}, {"msg", details}
    };
    const std::string payload = settings.format == "json"
        ? json_event.dump()
        : "CEF:0|CoPSeC|SecurityEngine|2.0|" + cef_escape(event_id) + "|" +
          cef_escape(description) + "|" + std::to_string(severity) + "|src=" + cef_escape(ip) +
          " act=" + cef_escape(action) + " msg=" + cef_escape(details);

    try {
        const std::filesystem::path path(settings.logfile);
        std::filesystem::create_directories(path.parent_path());
        std::ofstream output(settings.logfile, std::ios::out | std::ios::app);
        if (output.is_open()) output << payload << '\n';
    } catch (...) {
    }

    if (settings.host.empty() || settings.port == 0) return;
    addrinfo hints{};
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;
    addrinfo* result = nullptr;
    const std::string port = std::to_string(settings.port);
    if (getaddrinfo(settings.host.c_str(), port.c_str(), &hints, &result) != 0) return;
    const int socket_fd = socket(result->ai_family, SOCK_DGRAM, 0);
    if (socket_fd >= 0) {
        sendto(socket_fd, payload.data(), payload.size(), MSG_NOSIGNAL, result->ai_addr, result->ai_addrlen);
        close(socket_fd);
    }
    freeaddrinfo(result);
}

} // namespace copsec
