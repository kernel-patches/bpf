/* Copyright (c) 2022 ByteDance
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <linux/netdevice.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "trace_common.h"

#define MAX_ENTRIES 1000

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, long);
	__uint(max_entries, MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} touch_hash_no_prealloc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, long);
	__uint(max_entries, MAX_ENTRIES);
} touch_hash_prealloc SEC(".maps");

SEC("kprobe/" SYSCALL(sys_mount))
int stress_hmap_alloc(struct pt_regs *ctx)
{
	u32 key, i;
	long init_val = bpf_get_current_pid_tgid();

#pragma clang loop unroll(full)
	for (i = 0; i < MAX_ENTRIES; ++i) {
		key = i;
		bpf_map_update_elem(&touch_hash_no_prealloc,
							&key, &init_val, BPF_ANY);
	}

	return 0;
}

SEC("kprobe/" SYSCALL(sys_umount))
int stress_hmap_prealloc(struct pt_regs *ctx)
{
	u32 key, i;
	long init_val = bpf_get_current_pid_tgid();

#pragma clang loop unroll(full)
	for (i = 0; i < MAX_ENTRIES; ++i) {
		key = i;
		bpf_map_update_elem(&touch_hash_prealloc,
							&key, &init_val, BPF_ANY);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
