/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2021 Google */
#pragma once

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>
#include <string.h>

/*
 * Mock "real world" application.
 *
 * Blocks all writes from a set of applications. A limited number of newly
 * openat()ed file descriptors file descriptors may be written to. Writes to
 * already-open file descriptors are blocked.
 *
 * The affected processes are selected by populating filtered_pid.
 *
 * It is intended as an example of a stateful policy-enforcement application
 * which benefits from map tracing. It is not intended to be useful.
 */

/*
 * This is the only difference between the old and new application. Since we're
 * enforcing a policy based on this data, we want to migrate it. Since the
 * application can modify the data in parallel, we need to give this map
 * copy-on-write semantics so that those changes propagate.
 */
#if defined(OLD_VERSION)
struct allow_reads_key {
	uint32_t pid;
	int fd;
};
#else
struct allow_reads_key {
	int fd;
	uint32_t pid;
};
#endif
struct allow_reads_value {
	bool do_allow;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, struct allow_reads_key);
	__type(value, struct allow_reads_value);
} allow_reads SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, uint32_t);
	__type(value, bool);
} filtered_pids SEC(".maps");


SEC("kretprobe/__x64_sys_openat")
int BPF_KRETPROBE(kretprobe__x64_sys_openat, int ret)
{
	struct allow_reads_key key;
	struct allow_reads_value val;
	uint32_t pid;
	char *pid_is_filtered;

	pid = (bpf_get_current_pid_tgid() >> 32) & 0xFFFFFFFF;
	memset(&key, 0, sizeof(key));
	key.pid = pid;
	key.fd = ret;
	val.do_allow = true;

	if (ret < 0)
		return 0;

	pid_is_filtered = bpf_map_lookup_elem(&filtered_pids, &pid);
	if (!pid_is_filtered)
		return 0;

	if (!*pid_is_filtered)
		return 0;

	/*
	 * Ignore errors. Failing to insert has the effect of blocking writes
	 * on that file descriptor.
	 */
	bpf_map_update_elem(&allow_reads, &key, &val, /*flags=*/0);
	return 0;
}

SEC("fmod_ret/__x64_sys_write")
int BPF_PROG(fmod_ret__x64_sys_write, struct pt_regs *regs, int ret)
{
	int fd = PT_REGS_PARM1(regs);
	struct allow_reads_value *val;
	struct allow_reads_key key;

	memset(&key, 0, sizeof(key));
	key.pid = (bpf_get_current_pid_tgid() >> 32) & 0xFFFFFFFF;
	key.fd = fd;
	val = bpf_map_lookup_elem(&allow_reads, &key);
	if (!val)
		return -EPERM;
	return val->do_allow ? 0 : -EPERM;
}

SEC("fmod_ret/__x64_sys_close")
int BPF_PROG(fmod_ret__x64_sys_close, struct pt_regs *regs, int ret)
{
	int fd = PT_REGS_PARM1(regs);
	struct allow_reads_key key;
	struct allow_reads_value val;

	memset(&key, 0, sizeof(key));
	key.pid = (bpf_get_current_pid_tgid() >> 32) & 0xFFFFFFFF;
	key.fd = fd;
	val.do_allow = true;

	bpf_map_delete_elem(&allow_reads, &key);
	return 0;
}

char _license[] SEC("license") = "GPL";

