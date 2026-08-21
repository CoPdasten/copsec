#pragma once

#include <atomic>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "shm_guard.hpp"
#include "shm_common.hpp"

namespace copsec {

struct ThreatEvent {
    char ip[32] = {};
    char rule_id[64] = {};
    char mitre_tactic[64] = {};
    char mitre_technique[32] = {};
    char mitre_technique_name[96] = {};
    int32_t ban_duration = 0;
    int64_t timestamp_ms = 0;
};

struct SharedMemoryRegion {
    std::atomic<uint64_t> active_bans{0};
    std::atomic<uint64_t> total_bans{0};
    std::atomic<uint64_t> total_processed_lines{0};
    std::atomic<uint64_t> total_threats{0};
    std::atomic<uint64_t> rule_count{0};
    char recent_event[256]{};
    std::atomic<uint64_t> ring_count{0};
    std::atomic<uint64_t> ring_cursor{0};
    std::atomic<uint32_t> spin_lock{0};
    ThreatEvent ring[50]{};
    ShmGuard::Digest hmac{};
};

struct ShmSnapshot {
    uint64_t active_bans = 0;
    uint64_t total_processed_lines = 0;
    uint64_t total_threats = 0;
    uint64_t total_bans = 0;
    uint64_t rule_count = 0;
    uint64_t ring_count = 0;
    uint64_t memory_size = sizeof(SharedMemoryRegion);
    std::vector<ThreatEvent> events;
};

class ShmServer {
public:
    static ShmServer& get_instance() {
        static ShmServer instance;
        return instance;
    }

    ShmServer(const ShmServer&) = delete;
    ShmServer& operator=(const ShmServer&) = delete;
    ShmServer(ShmServer&&) = delete;
    ShmServer& operator=(ShmServer&&) = delete;

    ~ShmServer() {
        if (region_ != nullptr) {
            munmap(region_, sizeof(SharedMemoryRegion));
            region_ = nullptr;
        }
        if (fd_ >= 0) {
            close(fd_);
            fd_ = -1;
        }
    }

private:
    explicit ShmServer(const std::string& name = "/copsec_shm")
        : name_(name), fd_(-1), region_(nullptr) {
        initialize();
    }

public:

    bool initialize() {
        fd_ = shm_open(name_.c_str(), O_CREAT | O_RDWR, 0666);
        if (fd_ < 0) {
            return false;
        }
        if (fchmod(fd_, 0666) == -1) {
            close(fd_);
            fd_ = -1;
            return false;
        }

        if (ftruncate(fd_, static_cast<off_t>(sizeof(SharedMemoryRegion))) == -1) {
            close(fd_);
            fd_ = -1;
            return false;
        }

        region_ = static_cast<SharedMemoryRegion*>(mmap(nullptr, sizeof(SharedMemoryRegion),
            PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0));
        if (region_ == MAP_FAILED) {
            close(fd_);
            fd_ = -1;
            region_ = nullptr;
            return false;
        }

        region_->active_bans.store(0, std::memory_order_relaxed);
        region_->total_processed_lines.store(0, std::memory_order_relaxed);
        region_->total_threats.store(0, std::memory_order_relaxed);
        region_->total_bans.store(0, std::memory_order_relaxed);
        region_->rule_count.store(0, std::memory_order_relaxed);
        region_->ring_count.store(0, std::memory_order_relaxed);
        region_->ring_cursor.store(0, std::memory_order_relaxed);
        region_->spin_lock.store(0, std::memory_order_relaxed);
        for (auto& entry : region_->ring) {
            entry = ThreatEvent{};
        }
        std::memset(region_->recent_event, 0, sizeof(region_->recent_event));
        refresh_hmac();
        return true;
    }

    void update_metrics(uint64_t active_bans,
                        uint64_t total_processed_lines,
                        uint64_t total_threats,
                        uint64_t total_bans) {
        if (!region_) {
            return;
        }

        SpinMutex mutex(region_);
        SpinLockGuard guard(mutex);
        region_->active_bans.store(active_bans, std::memory_order_relaxed);
        region_->total_processed_lines.store(total_processed_lines, std::memory_order_relaxed);
        region_->total_threats.store(total_threats, std::memory_order_relaxed);
        region_->total_bans.store(total_bans, std::memory_order_relaxed);
        refresh_hmac();
    }

    void record_event(const std::string& ip,
                      const std::string& rule_id,
                      int32_t ban_duration,
                      int64_t timestamp_ms,
                      const std::string& mitre_tactic = {},
                      const std::string& mitre_technique = {},
                      const std::string& mitre_technique_name = {}) {
        if (!region_) {
            return;
        }

        SpinMutex mutex(region_);
        SpinLockGuard guard(mutex);
        ThreatEvent event{};
        std::snprintf(event.ip, sizeof(event.ip), "%s", ip.substr(0, sizeof(event.ip) - 1).c_str());
        std::snprintf(event.rule_id, sizeof(event.rule_id), "%s", rule_id.substr(0, sizeof(event.rule_id) - 1).c_str());
        std::snprintf(event.mitre_tactic, sizeof(event.mitre_tactic), "%s", mitre_tactic.substr(0, sizeof(event.mitre_tactic) - 1).c_str());
        std::snprintf(event.mitre_technique, sizeof(event.mitre_technique), "%s", mitre_technique.substr(0, sizeof(event.mitre_technique) - 1).c_str());
        std::snprintf(event.mitre_technique_name, sizeof(event.mitre_technique_name), "%s", mitre_technique_name.substr(0, sizeof(event.mitre_technique_name) - 1).c_str());
        event.ban_duration = ban_duration;
        event.timestamp_ms = timestamp_ms;
        std::snprintf(region_->recent_event, sizeof(region_->recent_event),
                  "%s rule=%s ip=%s", event.rule_id, event.ip, event.mitre_technique);

        const uint64_t cursor = region_->ring_cursor.load(std::memory_order_relaxed) % 50;
        region_->ring[cursor] = event;

        const uint64_t ring_count = region_->ring_count.load(std::memory_order_relaxed);
        if (ring_count < 50) {
            region_->ring_count.store(ring_count + 1, std::memory_order_relaxed);
        }
        region_->ring_cursor.store(cursor + 1, std::memory_order_relaxed);
        refresh_hmac();
    }

    void push_event(const std::string& ip, const std::string& rule_id, int32_t ban_duration,
                    const std::string& mitre_tactic = {}, const std::string& mitre_technique = {},
                    const std::string& mitre_technique_name = {}) {
        const auto now = std::chrono::system_clock::now();
        const auto ts_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
        record_event(ip, rule_id, ban_duration, ts_ms, mitre_tactic, mitre_technique, mitre_technique_name);
    }

    void increment_processed_lines(uint64_t delta = 1) {
        if (!region_) {
            return;
        }
        region_->total_processed_lines.fetch_add(delta, std::memory_order_relaxed);
        refresh_hmac();
    }

    void increment_threats(uint64_t delta = 1) {
        if (!region_) {
            return;
        }
        region_->total_threats.fetch_add(delta, std::memory_order_relaxed);
        refresh_hmac();
    }

    void increment_active_bans(int64_t delta) {
        if (!region_) {
            return;
        }
        region_->active_bans.fetch_add(delta, std::memory_order_relaxed);
        refresh_hmac();
    }

    void set_active_bans(uint64_t count) {
        if (!region_) return;
        region_->active_bans.store(count, std::memory_order_relaxed);
        refresh_hmac();
    }

    void update_active_bans(uint64_t count) {
        set_active_bans(count);
    }

    void update_rule_count(uint64_t count) {
        if (!region_) return;
        region_->rule_count.store(count, std::memory_order_relaxed);
        refresh_hmac();
    }

    void increment_total_bans(uint64_t delta = 1) {
        if (!region_) {
            return;
        }
        region_->total_bans.fetch_add(delta, std::memory_order_relaxed);
        refresh_hmac();
    }

    ShmSnapshot snapshot() const {
        ShmSnapshot snapshot;
        if (!region_) {
            return snapshot;
        }
        if (!verify_hmac()) return snapshot;

        const uint64_t ring_count = region_->ring_count.load(std::memory_order_relaxed);
        const uint64_t cursor = region_->ring_cursor.load(std::memory_order_relaxed);
        snapshot.active_bans = region_->active_bans.load(std::memory_order_relaxed);
        snapshot.total_processed_lines = region_->total_processed_lines.load(std::memory_order_relaxed);
        snapshot.total_threats = region_->total_threats.load(std::memory_order_relaxed);
        snapshot.total_bans = region_->total_bans.load(std::memory_order_relaxed);
        snapshot.rule_count = region_->rule_count.load(std::memory_order_relaxed);
        snapshot.ring_count = ring_count;
        snapshot.memory_size = sizeof(SharedMemoryRegion);

        const uint64_t active_events = std::min<uint64_t>(50ULL, ring_count);
        const uint64_t start = cursor < active_events ? 0 : (cursor - active_events) % 50;
        for (uint64_t i = 0; i < active_events; ++i) {
            const uint64_t idx = (start + i) % 50;
            snapshot.events.push_back(region_->ring[idx]);
        }
        return snapshot;
    }

    const std::string& name() const { return name_; }

private:
    static constexpr std::size_t payload_size() { return offsetof(SharedMemoryRegion, hmac); }

    void refresh_hmac() {
        if (!region_) return;
        region_->spin_lock.store(0, std::memory_order_relaxed);
        region_->hmac = guard_.sign(region_, payload_size());
    }

    bool verify_hmac() const {
        return region_ && guard_.verify(region_, payload_size(), region_->hmac);
    }

    class SpinMutex {
    public:
        explicit SpinMutex(SharedMemoryRegion* region) : region_(region) {}

        void lock() {
            while (region_->spin_lock.exchange(1, std::memory_order_acquire) != 0) {
                std::this_thread::yield();
            }
        }

        void unlock() {
            region_->spin_lock.store(0, std::memory_order_release);
        }

        SharedMemoryRegion* region_;
    };

    class SpinLockGuard {
    public:
        explicit SpinLockGuard(SpinMutex& mutex) : mutex_(mutex) { mutex_.lock(); }
        ~SpinLockGuard() { mutex_.unlock(); }
    private:
        SpinMutex& mutex_;
    };

    std::string name_;
    int fd_;
    SharedMemoryRegion* region_;
    mutable ShmGuard guard_;
};

class ShmClient {
public:
    explicit ShmClient(const std::string& name = "/copsec_shm")
        : name_(name), fd_(-1), region_(nullptr) {
        attach();
    }

    ~ShmClient() {
        if (region_ != nullptr) {
            munmap(region_, sizeof(SharedMemoryRegion));
            region_ = nullptr;
        }
        if (fd_ >= 0) {
            close(fd_);
            fd_ = -1;
        }
    }

    bool attach() {
        fd_ = shm_open(name_.c_str(), O_RDONLY, 0666);
        if (fd_ < 0) {
            return false;
        }

        region_ = static_cast<SharedMemoryRegion*>(mmap(nullptr, sizeof(SharedMemoryRegion),
            PROT_READ, MAP_SHARED, fd_, 0));
        if (region_ == MAP_FAILED) {
            close(fd_);
            fd_ = -1;
            region_ = nullptr;
            return false;
        }

        return true;
    }

    bool attached() const { return region_ != nullptr; }

    ShmSnapshot snapshot() const {
        ShmSnapshot snapshot{};
        if (!region_) {
            return snapshot;
        }

        snapshot.active_bans = region_->active_bans.load(std::memory_order_relaxed);
        snapshot.total_bans = region_->total_bans.load(std::memory_order_relaxed);
        snapshot.rule_count = region_->rule_count.load(std::memory_order_relaxed);
        snapshot.total_processed_lines = region_->total_processed_lines.load(std::memory_order_relaxed);
        snapshot.total_threats = region_->total_threats.load(std::memory_order_relaxed);
        snapshot.ring_count = region_->ring_count.load(std::memory_order_relaxed);
        snapshot.memory_size = sizeof(SharedMemoryRegion);

        const uint64_t active_events = std::min<uint64_t>(50ULL, snapshot.ring_count);
        const uint64_t cursor = region_->ring_cursor.load(std::memory_order_relaxed);
        const uint64_t start = cursor < active_events ? 0 : (cursor - active_events) % 50;
        for (uint64_t i = 0; i < active_events; ++i) {
            const uint64_t idx = (start + i) % 50;
            snapshot.events.push_back(region_->ring[idx]);
        }
        return snapshot;
    }

private:
    std::string name_;
    int fd_;
    SharedMemoryRegion* region_;
    ShmGuard guard_;
};

} // namespace copsec
