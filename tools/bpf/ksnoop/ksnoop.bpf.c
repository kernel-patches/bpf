// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021, Oracle and/or its affiliates. */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <asm/errno.h>
#include "ksnoop.h"

/* For kretprobes, the instruction pointer in the struct pt_regs context
 * is the kretprobe_trampoline, so to derive the instruction pointer
 * we need to push it onto a stack on entry and pop it on return.
 */
#define FUNC_MAX_STACK_DEPTH	(2 * MAX_FUNC_TRACES)

#define FUNC_MAX_PROCS		256

#ifndef NULL
#define NULL			0
#endif

struct func_stack {
	__u64 ips[FUNC_MAX_STACK_DEPTH];
	__u8 stack_depth;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FUNC_MAX_PROCS);
	__type(key, __u64);
	__type(value, struct func_stack);
} ksnoop_func_stack SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 8);
	__type(key, __u64);
	__type(value, struct trace);
} ksnoop_func_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(value_size, sizeof(int));
	__uint(key_size, sizeof(int));
} ksnoop_perf_map SEC(".maps");

/* function stacks are keyed on pid/tgid. Inlined to avoid verifier
 * complaint about global function not returing a scalar.
 */
static inline struct trace *get_trace(struct pt_regs *ctx, __u64 key,
				      bool entry)
{
	struct func_stack *func_stack, new = { 0 };
	struct trace *trace;
	__u64 ip;

	func_stack = bpf_map_lookup_elem(&ksnoop_func_stack, &key);
	if (!func_stack) {
		bpf_map_update_elem(&ksnoop_func_stack, &key, &new, 0);
		func_stack = bpf_map_lookup_elem(&ksnoop_func_stack, &key);
	}
	if (!func_stack) {
		bpf_printk("cannot retrieve func stack for tgid/pid %llx\n",
			   key);
		return NULL;
	}

	if (entry) {
		ip = KSNOOP_IP_FIX(PT_REGS_IP_CORE(ctx));
		/* push ip onto stack. return will pop it. */
		if (func_stack->stack_depth > FUNC_MAX_STACK_DEPTH) {
			bpf_printk("stackdepth %d exceeded for tgid/pid %llx\n",
				   func_stack->stack_depth, key);
			return NULL;
		}
		func_stack->ips[func_stack->stack_depth++] = ip;
	} else {
		/* retrieve ip from stack as IP in pt_regs is
		 * bpf kretprobe trampoline address.
		 */
		if (func_stack->stack_depth == 0 ||
		    func_stack->stack_depth > FUNC_MAX_STACK_DEPTH) {
			if (func_stack->stack_depth == 0)
				bpf_printk("no entry for tgid/pid %lld\n",
					   key);
			if (func_stack->stack_depth > FUNC_MAX_STACK_DEPTH)
				bpf_printk("stackdepth %d exceeded for tgid/pid %llx\n",
					   func_stack->stack_depth, key);
			return NULL;
		}
		ip = func_stack->ips[--func_stack->stack_depth];
	}

	return bpf_map_lookup_elem(&ksnoop_func_map, &ip);
}

static inline __u64 get_arg(struct pt_regs *ctx, enum arg argnum)
{
	switch (argnum) {
	case KSNOOP_ARG1:
		return PT_REGS_PARM1_CORE(ctx);
	case KSNOOP_ARG2:
		return PT_REGS_PARM2_CORE(ctx);
	case KSNOOP_ARG3:
		return PT_REGS_PARM3_CORE(ctx);
	case KSNOOP_ARG4:
		return PT_REGS_PARM4_CORE(ctx);
	case KSNOOP_ARG5:
		return PT_REGS_PARM5_CORE(ctx);
	case KSNOOP_RETURN:
		return PT_REGS_RC_CORE(ctx);
	default:
		return 0;
	}
}

static inline int ksnoop(struct pt_regs *ctx, bool entry)
{
	struct btf_ptr btf_ptr = { };
	struct trace *trace;
	struct func *func;
	__u16 trace_len;
	__u64 pid_tgid;
	__u64 data;
	int ret;
	__u8 i;

	pid_tgid = bpf_get_current_pid_tgid();
	trace = get_trace(ctx, pid_tgid, entry);
	if (!trace)
		return 0;

	trace->time = bpf_ktime_get_ns();
	trace->cpu = bpf_get_smp_processor_id();

	func = &trace->func;

	/* we may be tracing return and have already collected entry
	 * traces; such cases occur when we have a predicate on the
	 * return value _and_ we trace entry values.  In such cases
	 * we need to collect entry values but only report them if the
	 * predicate matches entry _and_ return predicates.  In such
	 * cases do not reset buf_len as we need to continue recording
	 * return values into the buffer along with the already-recorded
	 * entry values.
	 */
	if (!entry && (trace->flags & KSNOOP_F_STASH)) {
		if (trace->data_flags & KSNOOP_F_STASHED) {
			trace->data_flags &= ~KSNOOP_F_STASHED;
		} else {
			/* expected stashed data, predicate failed? */
			goto skiptrace;
		}
	} else {
		/* clear trace data before starting. */
		__builtin_memset(&trace->trace_data, 0,
				 sizeof(trace->trace_data));
		trace->data_flags = 0;
		trace->buf_len = 0;
		trace->buf[0] = '\0';
	}

	if (entry)
		trace->data_flags |= KSNOOP_F_ENTRY;
	else
		trace->data_flags |= KSNOOP_F_RETURN;


	for (i = 0; i < MAX_TRACES; i++) {
		struct trace_data *currdata;
		struct value *currtrace;
		char *buf_offset = NULL;
		void *dataptr;

		currdata = &trace->trace_data[i];
		currtrace = &trace->traces[i];

		/* skip irrelevant info (return value for entry etc) */
		if ((entry && !base_arg_is_entry(currtrace->base_arg)) ||
		    (!entry && base_arg_is_entry(currtrace->base_arg)))
			continue;

		/* skip void (unused) trace arguments, ensuring not to
		 * skip "void *".
		 */
		if (currtrace->type_id == 0 && currtrace->flags == 0)
			continue;

		data = get_arg(ctx, currtrace->base_arg);

		dataptr = (void *)data;

		if (currtrace->offset)
			dataptr += currtrace->offset;

		/* look up member value and read into data field, provided
		 * it <= size of a __u64; when it is, it can be used in
		 * predicate evaluation.
		 */
		if (currtrace->flags & KSNOOP_F_MEMBER) {
			ret = -EINVAL;
			data = 0;
			if (currtrace->size <= sizeof(__u64))
				ret = bpf_probe_read_kernel(&data,
							    currtrace->size,
							    dataptr);
			else
				bpf_printk("size was %d cant trace",
					   currtrace->size);
			if (ret) {
				currdata->err_type_id =
					currtrace->type_id;
				currdata->err = ret;
				continue;
			}
			if (currtrace->flags & KSNOOP_F_PTR)
				dataptr = (void *)data;
		}

		/* simple predicate evaluation: if any predicate fails,
		 * skip all tracing for this function.
		 */
		if (currtrace->flags & KSNOOP_F_PREDICATE_MASK) {
			bool ok = false;

			if (currtrace->flags & KSNOOP_F_PREDICATE_EQ &&
			    data == currtrace->predicate_value)
				ok = true;

			if (currtrace->flags & KSNOOP_F_PREDICATE_NOTEQ &&
			    data != currtrace->predicate_value)
				ok = true;

			if (currtrace->flags & KSNOOP_F_PREDICATE_GT &&
			    data > currtrace->predicate_value)
				ok = true;
			if (currtrace->flags & KSNOOP_F_PREDICATE_LT &&
			    data < currtrace->predicate_value)
				ok = true;

			if (!ok)
				goto skiptrace;
		}

		currdata->raw_value = data;

		if (currtrace->flags & (KSNOOP_F_PTR | KSNOOP_F_MEMBER))
			btf_ptr.ptr = dataptr;
		else
			btf_ptr.ptr = &data;

		btf_ptr.type_id = currtrace->type_id;

		if (trace->buf_len + MAX_TRACE_DATA >= MAX_TRACE_BUF)
			break;

		buf_offset = &trace->buf[trace->buf_len];
		if (buf_offset > &trace->buf[MAX_TRACE_BUF]) {
			currdata->err_type_id = currtrace->type_id;
			currdata->err = -ENOSPC;
			continue;
		}
		currdata->buf_offset = trace->buf_len;

		ret = bpf_snprintf_btf(buf_offset,
				       MAX_TRACE_DATA,
				       &btf_ptr, sizeof(btf_ptr),
				       BTF_F_PTR_RAW);
		if (ret < 0) {
			currdata->err_type_id = currtrace->type_id;
			currdata->err = ret;
			continue;
		} else if (ret < MAX_TRACE_DATA) {
			currdata->buf_len = ret + 1;
			trace->buf_len += ret + 1;
		} else {
			currdata->buf_len = MAX_TRACE_DATA;
			trace->buf_len += MAX_TRACE_DATA;
		}
	}

	/* we may be simply stashing values, and will report them
	 * on return; if so simply return without sending perf event.
	 * return will use remaining buffer space to fill in its values.
	 */
	if (entry && (trace->flags & KSNOOP_F_STASH)) {
		trace->data_flags |= KSNOOP_F_STASHED;
		return 0;
	}
	/* if a custom trace stores no trace info, no need to
	 * report perf event.  For default tracing case however
	 * we want to record function entry/return with no arguments
	 * or return values; in those cases trace data length is
	 * 0 but we want the entry/return events to be sent
	 * regardless.
	 */
	if ((trace->flags & KSNOOP_F_CUSTOM) && trace->buf_len == 0)
		goto skiptrace;

	trace->comm[0] = '\0';
	bpf_get_current_comm(trace->comm, sizeof(trace->comm));
	trace->pid = pid_tgid & 0xffffffff;
	/* trim perf event size to only contain data we've recorded. */
	trace_len = sizeof(*trace) + trace->buf_len - MAX_TRACE_BUF;
	if (trace_len > sizeof(*trace))
		goto skiptrace;
	ret = bpf_perf_event_output(ctx, &ksnoop_perf_map,
				    BPF_F_CURRENT_CPU,
				    trace, trace_len);
	if (ret < 0) {
		bpf_printk("could not send event for %s\n",
			   (const char *)func->name);
	}
skiptrace:
	trace->buf_len = 0;

	return 0;
}

SEC("kprobe/foo")
int kprobe_entry(struct pt_regs *ctx)
{
	return ksnoop(ctx, true);
}

SEC("kretprobe/foo")
int kprobe_return(struct pt_regs *ctx)
{
	return ksnoop(ctx, false);
}

char _license[] SEC("license") = "GPL";
