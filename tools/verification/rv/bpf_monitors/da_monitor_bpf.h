/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF support for DA monitors.
 *
 * BPF programs can include the in-kernel da_monitor directly, this
 * header contains all the BPF compatibility layer.
 *
 * Copyright (C) 2026 Red Hat Inc, Gabriele Monaco <gmonaco@redhat.com>
 */

#ifndef _DA_MONITOR_BPF_H
#define _DA_MONITOR_BPF_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_atomic.h"

/* BPF monitors don't support these */
#define rv_react(...) do {} while (0)
#define trace_rv_retries_error(...) do {} while (0)
#define pr_warn(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#define rv_monitoring_on() 1
#define da_implicit_guard()
#define IS_ENABLED(conf) 0

/*
 * Also used to filter out events higher values imply lower ones.
 * Userspace will parse this enum but expects EVENT to imply ERROR(s) and ERROR
 * to imply any other ERROR* type.
 */
enum rv_trace_type {
	RV_TRACE_NONE,
	RV_TRACE_ERROR,
	RV_TRACE_EVENT,
};

/* Configuration set from userspace before loading */
const volatile SEC(".rodata.trace_level") enum rv_trace_type trace_level = RV_TRACE_NONE;

/*
 * BPF ring buffer for trace events
 * Events and errors are sent to userspace via this ringbuf
 */
struct rv_trace_entry {
	uint8_t event_type;
	uint8_t is_final;
	char comm[TASK_COMM_LEN];
#if RV_MON_TYPE == RV_MON_PER_TASK || RV_MON_TYPE == RV_MON_PER_OBJ
	uint32_t id;
#endif
	uint32_t pid;
	uint32_t cpu;
	uint32_t curr_state;
	uint32_t event;
	uint32_t next_state;
};

#define rv_mon_map CONCATENATE(rv_mon_, MONITOR_NAME)
#define rv_rb CONCATENATE(rv_rb_, MONITOR_NAME)

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rv_rb SEC(".maps");

#ifndef __used
#define __used __attribute__((used))
#endif

/* Force types to be included in BTF for userspace parsing */
static const enum states __used _btf_states;
static const enum events __used _btf_events;
static const struct rv_trace_entry __used *_btf_trace;

static inline void da_monitor_reset(struct da_monitor *da_mon);

/* BPF monitors do not use reactors */
static inline void react(enum states curr_state, enum events event) { }

/*
 * BPF monitor implementations
 * These use BPF maps instead of kernel data structures
 */

#if RV_MON_TYPE == RV_MON_GLOBAL
/*
 * BPF Global monitor - uses a single-entry BPF array map
 */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, union rv_task_monitor);
} rv_mon_map SEC(".maps");

static inline struct da_monitor *da_get_monitor(void)
{
	__u32 key = 0;
	union rv_task_monitor *mon = bpf_map_lookup_elem(&rv_mon_map, &key);

	return &mon->da_mon;
}

#elif RV_MON_TYPE == RV_MON_PER_CPU
/*
 * BPF Per-CPU monitor - uses BPF per-cpu array map
 */

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, union rv_task_monitor);
} rv_mon_map SEC(".maps");

static inline struct da_monitor *da_get_monitor(void)
{
	__u32 key = 0;
	union rv_task_monitor *mon = bpf_map_lookup_elem(&rv_mon_map, &key);

	return &mon->da_mon;
}

#elif RV_MON_TYPE == RV_MON_PER_OBJ || RV_MON_TYPE == RV_MON_PER_TASK
/*
 * BPF Per-Object monitor - uses BPF hash map
 * Note: monitor_target_bpf type must be compatible with BPF
 * Types and structs must be different not to collide with vmlinux.h
 */

#if RV_MON_TYPE == RV_MON_PER_TASK
/*
 * BPF Per-Task monitor - uses BPF hash map indexed by PID
 *
 * Just a special case of per-object monitor with API consistent with in-kernel
 * monitors (no need to pass the id).
 */

#define da_get_monitor(tsk) da_get_monitor_bpf(BPF_CORE_READ(tsk, pid), tsk)
#define da_handle_event(tsk, event) \
	da_handle_event_bpf(BPF_CORE_READ(tsk, pid), tsk, event)
#define da_handle_start_event(tsk, event) \
	da_handle_start_event_bpf(BPF_CORE_READ(tsk, pid), tsk, event)
#define da_handle_start_run_event(tsk, event) \
	da_handle_start_run_event_bpf(BPF_CORE_READ(tsk, pid), tsk, event)

typedef struct task_struct *monitor_target_bpf;
static inline void da_destroy_storage(da_id_type id);

SEC("tp_btf/sched_process_exit")
int BPF_PROG(handle_obj_cleanup, struct task_struct *p, bool group_dead)
{
	da_destroy_storage(p->pid);
	return 0;
}

#else

#define da_get_monitor da_get_monitor_bpf
#define da_handle_event da_handle_event_bpf
#define da_handle_start_event da_handle_start_event_bpf
#define da_handle_start_run_event da_handle_start_run_event_bpf

#endif /* RV_MON_PER_TASK */

struct da_monitor_storage_bpf {
	da_id_type id;
	monitor_target_bpf target;
	union rv_task_monitor rv;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, da_id_type);
	__type(value, struct da_monitor_storage_bpf);
} rv_mon_map SEC(".maps");

static inline struct da_monitor *da_get_monitor_bpf(da_id_type id, monitor_target_bpf target)
{
	struct da_monitor_storage_bpf *storage;

	storage = bpf_map_lookup_elem(&rv_mon_map, &id);
	return storage ? &storage->rv.da_mon : NULL;
}

static inline struct da_monitor *da_create_storage(da_id_type id,
						    monitor_target_bpf target,
						    struct da_monitor *da_mon)
{
	struct da_monitor_storage_bpf new_storage = {
		.id = id,
		.target = target,
	};

	if (da_mon)
		return da_mon;

	bpf_map_update_elem(&rv_mon_map, &id, &new_storage, BPF_NOEXIST);
	return da_get_monitor_bpf(id, target);
}

static inline void da_destroy_storage(da_id_type id)
{
	bpf_map_delete_elem(&rv_mon_map, &id);
}

static inline da_id_type da_get_id(struct da_monitor *da_mon)
{
	return container_of(da_mon, struct da_monitor_storage_bpf, rv.da_mon)->id;
}

static inline monitor_target_bpf da_get_target(struct da_monitor *da_mon)
{
	return container_of(da_mon, struct da_monitor_storage_bpf, rv.da_mon)->target;
}

/*
 * Handle event for per object and per task
 */

static inline void __da_handle_event(struct da_monitor *da_mon,
				     enum events event, da_id_type id);
static inline bool __da_handle_start_event(struct da_monitor *da_mon,
					   enum events event, da_id_type id);
static inline bool __da_handle_start_run_event(struct da_monitor *da_mon,
					       enum events event, da_id_type id);

/*
 * da_handle_event - handle an event
 */
static inline void da_handle_event_bpf(da_id_type id, monitor_target_bpf target, enum events event)
{
	struct da_monitor *da_mon;

	da_mon = da_get_monitor_bpf(id, target);
	if (likely(da_mon))
		__da_handle_event(da_mon, event, id);
}

/*
 * da_handle_start_event - start monitoring or handle event
 *
 * This function is used to notify the monitor that the system is returning
 * to the initial state, so the monitor can start monitoring in the next event.
 * Thus:
 *
 * If the monitor already started, handle the event.
 * If the monitor did not start yet, start the monitor but skip the event.
 */
static inline bool da_handle_start_event_bpf(da_id_type id, monitor_target_bpf target,
					 enum events event)
{
	struct da_monitor *da_mon;

	da_mon = da_get_monitor_bpf(id, target);
	da_mon = da_create_storage(id, target, da_mon);
	if (unlikely(!da_mon))
		return 0;
	return __da_handle_start_event(da_mon, event, id);
}

/*
 * da_handle_start_run_event - start monitoring and handle event
 *
 * This function is used to notify the monitor that the system is in the
 * initial state, so the monitor can start monitoring and handling event.
 */
static inline bool da_handle_start_run_event_bpf(da_id_type id, monitor_target_bpf target,
					     enum events event)
{
	struct da_monitor *da_mon;

	da_mon = da_get_monitor_bpf(id, target);
	da_mon = da_create_storage(id, target, da_mon);
	if (unlikely(!da_mon))
		return 0;
	return __da_handle_start_run_event(da_mon, event, id);
}

static inline void da_reset_bpf(da_id_type id, monitor_target_bpf target)
{
	struct da_monitor *da_mon;

	da_mon = da_get_monitor_bpf(id, target);
	if (likely(da_mon))
		da_monitor_reset(da_mon);
}

#endif /* RV_MON_TYPE */

static inline void *_da_trace_common(enum states curr_state, enum events event,
				     enum rv_trace_type type)
{
	struct rv_trace_entry *entry;
	static const char stub_comm[] = "<XXX>";

	if (trace_level < type)
		return NULL;

	entry = bpf_ringbuf_reserve(&rv_rb, sizeof(*entry), 0);
	if (!entry)
		return NULL;
	entry->event_type = type;
	entry->cpu = bpf_get_smp_processor_id();
	entry->pid = bpf_get_current_pid_tgid() & 0xffffffff;
	if (bpf_get_current_comm(entry->comm, TASK_COMM_LEN))
		__builtin_memcpy(entry->comm, stub_comm, sizeof(stub_comm));
	entry->curr_state = curr_state;
	entry->event = event;

	return entry;
}

#if RV_MON_TYPE == RV_MON_PER_TASK || RV_MON_TYPE == RV_MON_PER_OBJ
static inline void _da_trace_id(struct rv_trace_entry *entry, da_id_type id)
{
	entry->id = id;
}
#else
static inline void _da_trace_id(struct rv_trace_entry *entry, da_id_type id) { }
#endif

/*
 * BPF trace events implementation using ring buffer
 */
static inline void da_trace_event(struct da_monitor *da_mon,
				  enum states curr_state, enum events event,
				  enum states next_state,
				  da_id_type id)
{
	struct rv_trace_entry *entry = _da_trace_common(curr_state, event, RV_TRACE_EVENT);

	if (!entry)
		return;
	_da_trace_id(entry, id);
	entry->is_final = model_is_final_state(next_state);
	entry->next_state = next_state;

	bpf_ringbuf_submit(entry, 0);
}

static inline void da_trace_error(struct da_monitor *da_mon,
				  enum states curr_state, enum events event,
				  da_id_type id)
{
	struct rv_trace_entry *entry = _da_trace_common(curr_state, event, RV_TRACE_ERROR);

	if (!entry)
		return;
	_da_trace_id(entry, id);

	bpf_ringbuf_submit(entry, 0);
}

/*
 * enable_monitor - BPF program to be called manually after all handlers are attached
 */
SEC("syscall")
int enable_monitor(void *ctx)
{
	rv_this.enabled = 1;
	return 0;
}

#endif // _DA_MONITOR_BPF_H
