#pragma once

#include <atomic>
#include <string>
#include "ebpf_monitor.hpp"

namespace copsec {

class ProcessMonitor {
public:
    explicit ProcessMonitor(EbpfMonitor& monitor);
    void start();
    void stop();
    std::uint64_t blocked_count() const;

private:
    void inspect(const EbpfMonitor::ExecEvent& event);
    static bool suspicious_binary(const std::string& filename);
    static bool web_context(std::uint32_t uid);
    EbpfMonitor& monitor_;
    std::atomic<bool> running_{false};
    std::atomic<std::uint64_t> blocked_{0};
};

} // namespace copsec
