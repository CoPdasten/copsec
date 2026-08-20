#include "suricata_watcher.hpp"

#include "bouncer.hpp"
#include "rate_limiter.hpp"
#include "shm_ipc.hpp"

#include <chrono>
#include <fcntl.h>
#include <fstream>
#include <nlohmann/json.hpp>
#include <poll.h>
#include <sys/stat.h>
#include <unistd.h>

namespace copsec {
namespace {

std::string mitre_technique_for_severity(std::uint32_t severity) {
    if (severity <= 1) return "T1595";
    if (severity == 2) return "T1190";
    return "T1059";
}

} // namespace

SuricataWatcher::SuricataWatcher(Bouncer& bouncer,
                                 ShmServer& shm_server,
                                                                 RateLimiter& rate_limiter,
                                 std::string eve_path)
        : bouncer_(bouncer), shm_server_(shm_server), rate_limiter_(rate_limiter),
            eve_path_(std::move(eve_path)) {}

SuricataWatcher::~SuricataWatcher() {
    stop();
}

bool SuricataWatcher::start() {
    if (running_.exchange(true)) return false;
    watcher_thread_ = std::thread(&SuricataWatcher::watch_loop, this);
    return true;
}

void SuricataWatcher::stop() {
    running_.store(false, std::memory_order_release);
    if (watcher_thread_.joinable()) watcher_thread_.join();
}

void SuricataWatcher::watch_loop() {
    const int fd = open(eve_path_.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        running_.store(false, std::memory_order_release);
        return;
    }

    const off_t initial_end = lseek(fd, 0, SEEK_END);
    if (initial_end < 0) {
        close(fd);
        running_.store(false, std::memory_order_release);
        return;
    }

    std::string pending;
    char buffer[8192];
    struct pollfd descriptor{fd, POLLIN, 0};

    while (running_.load(std::memory_order_acquire)) {
        const int poll_result = poll(&descriptor, 1, 250);
        if (poll_result < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (poll_result == 0) continue;
        if ((descriptor.revents & (POLLERR | POLLNVAL)) != 0) break;
        if ((descriptor.revents & POLLIN) == 0) continue;

        for (;;) {
            const ssize_t bytes_read = read(fd, buffer, sizeof(buffer));
            if (bytes_read > 0) {
                pending.append(buffer, static_cast<std::size_t>(bytes_read));
                std::size_t newline = 0;
                while ((newline = pending.find('\n')) != std::string::npos) {
                    const std::string line = pending.substr(0, newline);
                    pending.erase(0, newline + 1);
                    try {
                        const auto object = nlohmann::json::parse(line);
                        if (object.value("event_type", "") != "alert") continue;

                        SuricataAlert alert;
                        alert.src_ip = object.value("src_ip", "");
                        alert.dest_ip = object.value("dest_ip", "");
                        alert.protocol = object.value("proto", "");
                        const auto& alert_object = object.at("alert");
                        alert.signature = alert_object.value("signature", "");
                        alert.category = alert_object.value("category", "");
                        alert.signature_id = alert_object.value("signature_id", 0U);
                        alert.severity = alert_object.value("severity", 3U);
                        if (!alert.src_ip.empty()) handle_alert(alert);
                    } catch (const nlohmann::json::exception&) {
                        continue;
                    }
                }
                continue;
            }
            if (bytes_read < 0 && errno == EINTR) continue;
            break;
        }
    }

    close(fd);
}

void SuricataWatcher::handle_alert(const SuricataAlert& alert) {
    const std::string technique = mitre_technique_for_severity(alert.severity);
    shm_server_.increment_threats(1);
    shm_server_.push_event(alert.src_ip, "suricata-alert", 3600, "Defense Evasion", technique);
    rate_limiter_.check_rate_limit(alert.src_ip, 100, std::chrono::seconds(60));

    if (alert.severity <= 2) {
        bouncer_.ban_ip(alert.src_ip, 3600, "suricata-alert");
    }
}

} // namespace copsec
