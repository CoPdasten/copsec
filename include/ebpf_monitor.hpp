#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>

namespace copsec {

class EbpfMonitor {
public:
    EbpfMonitor() = default;
    ~EbpfMonitor();

    EbpfMonitor(const EbpfMonitor&) = delete;
    EbpfMonitor& operator=(const EbpfMonitor&) = delete;

    bool start();
    void stop();

private:
    void run();

    std::atomic<bool> running_{false};
    std::thread thread_;
    void* object_ = nullptr;
    void* ring_buffer_ = nullptr;
};

} // namespace copsec