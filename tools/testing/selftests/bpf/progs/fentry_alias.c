// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

struct task_struct {
	int tgid;
} __attribute__((preserve_access_index));

int real_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u64);
	__type(value, __u64);
} map SEC(".maps");

/* test1 - glob var relocations */
__u64 test1_hit_cnt = 0;

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(test1, int a)
{
	test1_hit_cnt++;
	return 0;
}

int test1_alias(int a) __attribute__((alias("test1")));

/* test2 - map relocations */
SEC("fentry/bpf_fentry_test1")
int BPF_PROG(test2, int a)
{
	__u64 key = 0, *value, new_value;

	value = bpf_map_lookup_elem(&map, &key);
	new_value = value ? *value + 1 : 1;
	bpf_map_update_elem(&map, &key, &new_value, 0);
	return 0;
}

int test2_alias(int a) __attribute__((alias("test2")));

/* test3 - subprog relocations */
__u64 test3_hit_cnt = 0;

static __noinline void test3_subprog(void)
{
	test3_hit_cnt++;
}

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(test3, int a)
{
	test3_subprog();
	return 0;
}

int test3_alias(int a) __attribute__((alias("test3")));

/* test4 - CO-RE relocations */
__u64 test4_hit_cnt = 0;

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(test4, int a)
{
	struct task_struct *task;
	int pid;

	task = (void *)bpf_get_current_task();
	pid = BPF_CORE_READ(task, tgid);

	if (pid == real_pid)
		test4_hit_cnt++;

	return 0;
}

int test4_alias(int a) __attribute__((alias("test4")));
