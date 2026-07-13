#include "vmlinux.h"
#include "profiler.h"
#include "shared_maps.h"
#include "shared_helpers.h"
#include "tracers.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

typedef struct {
    u32 tid;
} mmap_data_key_t;

typedef struct {
    u64 start_address;
    u64 end_address;
} mmap_data_value_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 0);
} tracer_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} tracer_events_rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 500);
    __type(key, mmap_data_key_t);
    __type(value, mmap_data_value_t);
} tracked_munmap SEC(".maps");

// Arguments from
// /sys/kernel/debug/tracing/events/syscalls/sys_enter_munmap/format
struct munmap_entry_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    unsigned long addr;
    size_t len;
};

SEC("tracepoint/sched/sched_process_exit")
int tracer_process_exit(void *ctx) {
    struct task_struct *task = current_task();
    unsigned int level = lightswitch_config.userspace_pid_ns_level;
    int per_process_id = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level].nr);
    int per_thread_id = BPF_CORE_READ(task, thread_pid, numbers[level].nr);

    if (!process_is_known(per_process_id)) {
        return 0;
    }

    // Only report main thread terminating.
    if (per_process_id != per_thread_id) {
        return 0;
    }

    tracer_event_t event = {
        .type = TRACER_EVENT_TYPE_PROCESS_EXIT,
        .pid = per_process_id,
        .start_address = 0,
    };

    int ret = 0;
    if (lightswitch_config.use_ring_buffers) {
        ret = bpf_ringbuf_output(&tracer_events_rb, &event, sizeof(tracer_event_t), 0);
    } else {
        ret = bpf_perf_event_output(ctx, &tracer_events, BPF_F_CURRENT_CPU, &event, sizeof(tracer_event_t));
    }
    if (ret < 0) {
        LOG("[error] failed to send process exit tracer event");
        return 0;
    }

    LOG("[debug] sent process exit tracer event");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_munmap")
int tracer_enter_munmap(struct munmap_entry_args *args) {
    u64 start_address = args->addr;
    u64 end_address = args->addr + args->len;

    struct task_struct *task = current_task();
    unsigned int level = lightswitch_config.userspace_pid_ns_level;
    int per_process_id = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level].nr);

    // We might not know about some mappings, but also we definitely don't want to notify
    // of non-executable mappings being unmapped.
    mapping_t *mapping = find_mapping(per_process_id, start_address);
    if (mapping == NULL) {
        return 0;
    }

    // Ensure we didn't get a process entry.
    if (start_address < mapping->begin || start_address >= mapping->end) {
        return 0;
    }

    int per_thread_id = BPF_CORE_READ(task, thread_pid, numbers[level].nr);
    mmap_data_key_t key = {
        .tid = per_thread_id,
    };
    mmap_data_value_t value = {
        .start_address = start_address,
        .end_address = end_address,
    };
    bpf_map_update_elem(&tracked_munmap, &key, &value, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_munmap")
int tracer_exit_munmap(struct syscall_trace_exit *ctx) {
    struct task_struct *task = current_task();
    unsigned int level = lightswitch_config.userspace_pid_ns_level;
    int per_thread_id = BPF_CORE_READ(task, thread_pid, numbers[level].nr);

    mmap_data_key_t key = {
        .tid = per_thread_id,
    };

    mmap_data_value_t *value = bpf_map_lookup_elem(&tracked_munmap, &key);
    if (value == NULL) {
        return 0;
    }

    if (ctx->ret != 0) {
        bpf_map_delete_elem(&tracked_munmap, &key);
        return 0;
    }

    LOG("[debug] sending munmap event");

    int per_process_id = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level].nr);
    tracer_event_t event = {
        .type = TRACER_EVENT_TYPE_MUNMAP,
        .pid = per_process_id,
        .start_address = value->start_address,
        .end_address = value->end_address,
    };

    int ret;

    if (lightswitch_config.use_ring_buffers) {
        ret = bpf_ringbuf_output(&tracer_events_rb, &event, sizeof(tracer_event_t), 0);
    } else {
        ret = bpf_perf_event_output(ctx, &tracer_events, BPF_F_CURRENT_CPU, &event, sizeof(tracer_event_t));
    }
    if (ret < 0) {
        LOG("[error] failed to send munmap tracer event");
    }

    bpf_map_delete_elem(&tracked_munmap, &key);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
