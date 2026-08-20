#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct exec_event {
    __u32 pid;
    __u32 uid;
    char filename[256];
};

struct trace_event_raw_sys_enter {
    __u64 unused;
    __u64 syscall_nr;
    __u64 args[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} exec_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx) {
    const char* filename = (const char*)ctx->args[0];
    struct exec_event* event = bpf_ringbuf_reserve(&exec_events, sizeof(*event), 0);
    if (!event) return 0;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid();
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);

    if (event->filename[0] == '/' &&
        ((event->filename[1] == 't' && event->filename[2] == 'm' && event->filename[3] == '/') ||
         (event->filename[1] == 'd' && event->filename[2] == 'e' && event->filename[3] == 'v' && event->filename[4] == '/' && event->filename[5] == 's' && event->filename[6] == 'h' && event->filename[7] == 'm' && event->filename[8] == '/') ||
         (event->filename[1] == 'v' && event->filename[2] == 'a' && event->filename[3] == 'r' && event->filename[4] == '/' && event->filename[5] == 't' && event->filename[6] == 'm' && event->filename[7] == 'p' && event->filename[8] == '/'))) {
        bpf_ringbuf_submit(event, 0);
    } else {
        bpf_ringbuf_discard(event, 0);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";