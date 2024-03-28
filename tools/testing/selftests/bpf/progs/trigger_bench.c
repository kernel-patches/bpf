// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Facebook
#include <linux/bpf.h>
#include <asm/unistd.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

#define CPU_MASK 255
#define MAX_CPUS (CPU_MASK + 1) /* should match MAX_BUCKETS in benchs/bench_trigger.c */

/* matches struct counter in bench.h */
struct counter {
	long value;
} __attribute__((aligned(128)));

struct counter hits[MAX_CPUS];

static __always_inline void inc_counter(void)
{
	int cpu = bpf_get_smp_processor_id();

	__sync_add_and_fetch(&hits[cpu & CPU_MASK].value, 1);
}

static __always_inline void inc_counter2(int amount)
{
	int cpu = bpf_get_smp_processor_id();

	__sync_add_and_fetch(&hits[cpu & CPU_MASK].value, amount);
}

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
        __type(key, int);
        __type(value, int);
        __uint(max_entries, 1);
} hash_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key, int);
        __type(value, int);
        __uint(max_entries, 1);
} array_map SEC(".maps");

static int zero = 0;

static void __always_inline hash_inc(void *map) {
        int *p;

        p = bpf_map_lookup_elem(map, &zero);
        if (!p) {
                bpf_map_update_elem(map, &zero, &zero, BPF_ANY);
                p = bpf_map_lookup_elem(map, &zero);
                if (!p)
                        return;
        }
        *p += 1;
}

struct counter arr[256];

static void __always_inline glob_arr_inc(void) {
	int cpu = bpf_get_smp_processor_id();

	arr[cpu].value += 1;
}

SEC("?uprobe")
int bench_trigger_uprobe(void *ctx)
{
	inc_counter();
	return 0;
}

const volatile int batch_iters = 0;

SEC("?raw_tp")
int trigger_arr_inc(void *ctx)
{
	int i;

	for (i = 0; i < batch_iters; i++)
		hash_inc(&array_map);

	inc_counter2(batch_iters);

	return 0;
}

SEC("?raw_tp")
int trigger_hash_inc(void *ctx)
{
	int i;

	for (i = 0; i < batch_iters; i++)
		hash_inc(&hash_map);

	inc_counter2(batch_iters);

	return 0;
}

SEC("?raw_tp")
int trigger_glob_arr_inc(void *ctx)
{
	int i;

	for (i = 0; i < batch_iters; i++)
		glob_arr_inc();

	inc_counter2(batch_iters);

	return 0;
}

SEC("?raw_tp")
int trigger_count(void *ctx)
{
	int i;

	for (i = 0; i < batch_iters; i++)
		inc_counter();

	return 0;
}

SEC("?raw_tp")
int trigger_driver(void *ctx)
{
	int i;

	for (i = 0; i < batch_iters; i++)
		(void)bpf_get_numa_node_id(); /* attach point for benchmarking */

	return 0;
}

extern int bpf_modify_return_test_tp(int nonce) __ksym __weak;

SEC("?raw_tp")
int trigger_driver_kfunc(void *ctx)
{
	int i;

	for (i = 0; i < batch_iters; i++)
		(void)bpf_modify_return_test_tp(0); /* attach point for benchmarking */

	return 0;
}

SEC("?kprobe/bpf_get_numa_node_id")
int bench_trigger_kprobe(void *ctx)
{
	inc_counter();
	return 0;
}

SEC("?kretprobe/bpf_get_numa_node_id")
int bench_trigger_kretprobe(void *ctx)
{
	inc_counter();
	return 0;
}

SEC("?kprobe.multi/bpf_get_numa_node_id")
int bench_trigger_kprobe_multi(void *ctx)
{
	inc_counter();
	return 0;
}

SEC("?kretprobe.multi/bpf_get_numa_node_id")
int bench_trigger_kretprobe_multi(void *ctx)
{
	inc_counter();
	return 0;
}

SEC("?fentry/bpf_get_numa_node_id")
int bench_trigger_fentry(void *ctx)
{
	inc_counter();
	return 0;
}

SEC("?fexit/bpf_get_numa_node_id")
int bench_trigger_fexit(void *ctx)
{
	inc_counter();
	return 0;
}

SEC("?fmod_ret/bpf_modify_return_test_tp")
int bench_trigger_fmodret(void *ctx)
{
	inc_counter();
	return -22;
}

SEC("?tp/bpf_test_run/bpf_trigger_tp")
int bench_trigger_tp(void *ctx)
{
	inc_counter();
	return 0;
}

SEC("?raw_tp/bpf_trigger_tp")
int bench_trigger_rawtp(void *ctx)
{
	inc_counter();
	return 0;
}
