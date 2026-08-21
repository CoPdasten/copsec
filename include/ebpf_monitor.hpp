#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <functional>

namespace copsec {

class EbpfMonitor {
public:
    struct ExecEvent { std::uint32_t pid; std::uint32_t uid; std::string filename; };
    using ExecCallback = std::function<void(const ExecEvent&)>;
    EbpfMonitor() = default;
    ~EbpfMonitor();

    EbpfMonitor(const EbpfMonitor&) = delete;
    EbpfMonitor& operator=(const EbpfMonitor&) = delete;

    bool start();
    void stop();
    void set_exec_callback(ExecCallback callback);
    void dispatch_exec_event(const ExecEvent& event);

private:
    void run();

    std::atomic<bool> running_{false};
    std::thread thread_;
    void* object_ = nullptr;
    void* ring_buffer_ = nullptr;
    ExecCallback callback_;
};

} // namespace copsec