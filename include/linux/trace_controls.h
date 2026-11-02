/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TRACE_CONTROLS_H
#define _LINUX_TRACE_CONTROLS_H


/*
 * General tracing related utility functions - trace_printk(),
 * tracing_on/tracing_off and tracing_start()/tracing_stop
 *
 * Use tracing_on/tracing_off when you want to quickly turn on or off
 * tracing. It simply enables or disables the recording of the trace events.
 * This also corresponds to the user space /sys/kernel/tracing/tracing_on
 * file, which gives a means for the kernel and userspace to interact.
 * Place a tracing_off() in the kernel where you want tracing to end.
 * From user space, examine the trace, and then echo 1 > tracing_on
 * to continue tracing.
 *
 * tracing_stop/tracing_start has slightly more overhead. It is used
 * by things like suspend to ram where disabling the recording of the
 * trace is not enough, but tracing must actually stop because things
 * like calling smp_processor_id() may crash the system.
 *
 * Most likely, you want to use tracing_on/tracing_off.
 */
enum ftrace_dump_mode {
	DUMP_NONE,
	DUMP_ALL,
	DUMP_ORIG,
	DUMP_PARAM,
};

#ifdef CONFIG_TRACING
void tracing_on(void);
void tracing_off(void);
int tracing_is_on(void);
void tracing_snapshot(void);
void tracing_snapshot_alloc(void);
void tracing_start(void);
void tracing_stop(void);
void trace_dump_stack(int skip);
void ftrace_dump(enum ftrace_dump_mode oops_dump_mode);
#else
static inline void tracing_start(void) { }
static inline void tracing_stop(void) { }
static inline void tracing_on(void) { }
static inline void tracing_off(void) { }
static inline int tracing_is_on(void) { return 0; }
static inline void tracing_snapshot(void) { }
static inline void tracing_snapshot_alloc(void) { }
static inline void trace_dump_stack(int skip) { }
static inline void ftrace_dump(enum ftrace_dump_mode oops_dump_mode) { }
#endif

#endif /* _LINUX_TRACE_CONTROLS_H */
