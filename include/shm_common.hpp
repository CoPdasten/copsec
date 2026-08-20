#pragma once

#include <atomic>
#include <cstdint>

namespace copsec {

inline constexpr char COPSEC_SHM_NAME[] = "/copsec_shm";

struct ShmTelemetry {
    std::atomic<uint64_t> total_processed_lines{0};
    std::atomic<uint64_t> threat_detections{0};
    std::atomic<uint64_t> active_bans{0};
    std::atomic<uint64_t> total_bans{0};
    char recent_event[256]{};
};

} // namespace copsec
