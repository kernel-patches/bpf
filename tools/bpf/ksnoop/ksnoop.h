/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2021, Oracle and/or its affiliates. */

#define MAX_FUNC_TRACES			8

enum arg {
	KSNOOP_ARG1,
	KSNOOP_ARG2,
	KSNOOP_ARG3,
	KSNOOP_ARG4,
	KSNOOP_ARG5,
	KSNOOP_RETURN
};

/* we choose "return" as the name for the returned value because as
 * a C keyword it can't clash with a function entry parameter.
 */
#define KSNOOP_RETURN_NAME		"return"

/* if we can't get a type id for a type (such as module-specific type)
 * mark it as KSNOOP_ID_UNKNOWN since BTF lookup in bpf_snprintf_btf()
 * will fail and the data will be simply displayed as a __u64.
 */
#define KSNOOP_ID_UNKNOWN		0xffffffff

#define MAX_STR				256
#define MAX_VALUES			6
#define MAX_ARGS			(MAX_VALUES - 1)
#define KSNOOP_F_PTR			0x1	/* value is a pointer */
#define KSNOOP_F_MEMBER			0x2	/* member reference */
#define KSNOOP_F_ENTRY			0x4
#define KSNOOP_F_RETURN			0x8
#define KSNOOP_F_CUSTOM			0x10	/* custom trace */

#define KSNOOP_F_STASH			0x20	/* store values on entry, don't
						 * send perf event
						 */
#define KSNOOP_F_STASHED		0x40	/* values stored on entry */

#define KSNOOP_F_PREDICATE_EQ		0x100
#define KSNOOP_F_PREDICATE_NOTEQ	0x200
#define KSNOOP_F_PREDICATE_GT		0x400
#define KSNOOP_F_PREDICATE_LT		0x800

#define KSNOOP_F_PREDICATE_MASK		(KSNOOP_F_PREDICATE_EQ | \
					 KSNOOP_F_PREDICATE_NOTEQ | \
					 KSNOOP_F_PREDICATE_GT | \
					 KSNOOP_F_PREDICATE_LT)

/* for kprobes, entry is function IP + 1, subtract 1 in BPF prog context */
#define KSNOOP_IP_FIX(ip)		(ip - 1)

struct value {
	char name[MAX_STR];
	enum arg base_arg;
	__u32 size;
	__u32 offset;
	__u64 type_id;
	__u64 flags;
	__u64 predicate_value;
};

struct func {
	char name[MAX_STR];
	char mod[MAX_STR];
	__u8 nr_args;
	__u64 ip;
	struct value args[MAX_VALUES];
};

#define MAX_TRACES MAX_VALUES

#define MAX_TRACE_DATA	2048

struct trace_data {
	__u64 raw_value;
	__u32 err_type_id;	/* type id we can't dereference */
	int err;
	__u32 buf_offset;
	__u16 buf_len;
};

#define MAX_TRACE_BUF	(MAX_TRACES * MAX_TRACE_DATA)

struct trace {
	/* initial values are readonly in tracing context */
	struct btf *btf;
	struct func func;
	__u8 nr_traces;
	struct value traces[MAX_TRACES];
	__u64 flags;
	/* ...whereas values below this point are set or modified
	 * in tracing context
	 */
	__u64 time;
	__u32 cpu;
	__u32 pid;
	char comm[MAX_STR];
	__u64 data_flags;
	struct trace_data trace_data[MAX_TRACES];
	__u16 buf_len;
	char buf[MAX_TRACE_BUF];
};

#define PAGES_DEFAULT	8

static inline int base_arg_is_entry(enum arg base_arg)
{
	return base_arg != KSNOOP_RETURN;
}
