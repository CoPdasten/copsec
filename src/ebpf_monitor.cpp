#include "ebpf_monitor.hpp"

#include "logger.hpp"

#include <cstring>
#include <cerrno>
#include <filesystem>

#ifdef COPSEC_HAS_LIBBPF
#include <bpf/libbpf.h>
#include <unistd.h>

namespace {
struct ExecEvent {
    uint32_t pid;
    uint32_t uid;
    char filename[256];
};

int handle_exec_event(void* user_data, void* data, size_t size) {
    if (size < sizeof(ExecEvent)) return 0;
    const auto* event = static_cast<const ExecEvent*>(data);
    auto* monitor = static_cast<copsec::EbpfMonitor*>(user_data);
    if (monitor) monitor->dispatch_exec_event({event->pid, event->uid, event->filename});
    copsec::Logger::get_instance().log(
        copsec::LogLevel::WARN,
        "SUSPICIOUS_EXEC",
        std::string("Executable launched from a sensitive directory: ") + event->filename,
        "HIGH",
        "alerted",
        "",
        "",
        "",
        1,
        0,
        "Execution",
        "TA0002",
        "T1059",
        "Command and Scripting Interpreter",
        "https://attack.mitre.org/techniques/T1059/",
        "sys_enter_execve",
        event->filename,
        "endpoint");
    return 0;
}
}
#endif

namespace copsec {

namespace {
#ifdef COPSEC_HAS_LIBBPF
std::string find_monitor_object() {
    for (const auto& path : {"/etc/copsec/copsec_ringbuf.bpf.o", "config/copsec_ringbuf.bpf.o", "build/bpf/copsec_ringbuf.bpf.o",
                             "/etc/copsec/copsec_kprobe.bpf.o", "config/copsec_kprobe.bpf.o", "build/bpf/copsec_kprobe.bpf.o"}) {
        if (std::filesystem::is_regular_file(path)) return path;
    }
    return {};
}
#endif
}

EbpfMonitor::~EbpfMonitor() {
    stop();
}

bool EbpfMonitor::start() {
    if (running_) return false;

#ifndef COPSEC_HAS_LIBBPF
    Logger::get_instance().log(LogLevel::INFO, "EBPF_INIT",
        "libbpf is unavailable; process tracing disabled, nftables enforcement remains active.");
    return true;
#else
    const std::string object_path = find_monitor_object();
    if (object_path.empty()) {
        Logger::get_instance().log(LogLevel::INFO, "EBPF_INIT",
            "kprobe object is unavailable; process tracing disabled, nftables enforcement remains active.");
        return true;
    }

    auto* object = bpf_object__open_file(object_path.c_str(), nullptr);
    if (!object || bpf_object__load(object) != 0) {
        Logger::get_instance().log(LogLevel::INFO, "EBPF_INIT",
            "Unable to load process tracing program; nftables enforcement remains active.");
        if (object) bpf_object__close(object);
        return true;
    }

    auto* program = bpf_object__find_program_by_name(object, "tracepoint__syscalls__sys_enter_execve");
    auto* events = bpf_object__find_map_by_name(object, "exec_events");
    if (!program || !events) {
        Logger::get_instance().log(LogLevel::INFO, "EBPF_INIT",
            "Process tracing object is incomplete; nftables enforcement remains active.");
        bpf_object__close(object);
        return true;
    }

    bpf_link* link = bpf_program__attach_tracepoint(program, "syscalls", "sys_enter_execve");
    if (!link || libbpf_get_error(link)) {
        Logger::get_instance().log(LogLevel::INFO, "EBPF_INIT",
            "sys_enter_execve attachment denied; nftables enforcement remains active.");
        bpf_object__close(object);
        return true;
    }

    ring_buffer* ring = ring_buffer__new(bpf_map__fd(events), handle_exec_event, this, nullptr);
    if (!ring || libbpf_get_error(ring)) {
        Logger::get_instance().log(LogLevel::INFO, "EBPF_INIT",
            "eBPF ring buffer unavailable; nftables enforcement remains active.");
        bpf_link__destroy(link);
        bpf_object__close(object);
        return true;
    }

    object_ = object;
    ring_buffer_ = ring;
    running_ = true;
    thread_ = std::thread(&EbpfMonitor::run, this);
    Logger::get_instance().log(LogLevel::INFO, "EBPF_INIT", "sys_enter_execve process monitor attached.");
    return true;
#endif
}

void EbpfMonitor::set_exec_callback(ExecCallback callback) {
    callback_ = std::move(callback);
}

void EbpfMonitor::dispatch_exec_event(const ExecEvent& event) {
    if (callback_) callback_(event);
}

void EbpfMonitor::stop() {
    if (!running_.exchange(false)) return;
    if (thread_.joinable()) thread_.join();

#ifdef COPSEC_HAS_LIBBPF
    auto* ring = static_cast<ring_buffer*>(ring_buffer_);
    if (ring) ring_buffer__free(ring);
    ring_buffer_ = nullptr;
    if (object_) bpf_object__close(static_cast<bpf_object*>(object_));
    object_ = nullptr;
#endif
}

void EbpfMonitor::run() {
#ifdef COPSEC_HAS_LIBBPF
    auto* ring = static_cast<ring_buffer*>(ring_buffer_);
    while (running_) {
        const int result = ring_buffer__poll(ring, 250);
        if (result < 0 && result != -EINTR) {
            Logger::get_instance().log(LogLevel::INFO, "EBPF_RUNTIME",
                "Process tracing stopped; nftables enforcement remains active.");
            break;
        }
    }
#endif
}

} // namespace copsec