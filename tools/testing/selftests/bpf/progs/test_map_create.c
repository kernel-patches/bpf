/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2021 Hengqi Chen */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define MAX_ENTRIES	8

struct {
	__uint(type,BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, int);
	__type(value, int);
} map1 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, int);
	__type(value, __u64);
} map2 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, int);
	__type(value, int);
} map3 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, int);
	__type(value, int);
	__array(values, struct {
		__uint(type, BPF_MAP_TYPE_ARRAY);
		__uint(max_entries, 1);
		__type(key, __u32);
		__type(value, __u32);
	});
} map4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, int);
	__type(value, int);
	__array(values, struct {
		__uint(type, BPF_MAP_TYPE_ARRAY);
		__uint(max_entries, 1);
		__type(key, __u32);
		__type(value, __u32);
	});
} map5 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, int);
	__type(value, int);
} map6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, int);
	__type(value, int);
} map7 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, int);
	__type(value, int);
} map8 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, int);
	__type(value, int);
} map9 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, int);
	__type(value, int);
} map10 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, MAX_ENTRIES);
	__type(value, int);
} map11 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK);
	__uint(max_entries, MAX_ENTRIES);
	__type(value, int);
} map12 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, int);
	__type(value, int);
} map13 SEC(".maps");

char _license[] SEC("license") = "GPL";
