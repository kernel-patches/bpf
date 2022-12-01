// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Google */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
	__uint(max_entries, 32);
	__type(key, int);
	__type(value, int);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} repinned_dev_map SEC(".maps");


char _license[] SEC("license") = "GPL";
