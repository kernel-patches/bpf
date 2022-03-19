// SPDX-License-Identifier: GPL-2.0-only
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include <test_maps.h>

struct map_attr {
	__u32 map_type;
	char *map_name;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
};

static struct map_attr attrs[] = {
	{BPF_MAP_TYPE_HASH, "BPF_MAP_TYPE_HASH", 4, 4, 10},
	{BPF_MAP_TYPE_ARRAY, "BPF_MAP_TYPE_ARRAY", 4, 4, 10},
	{BPF_MAP_TYPE_PROG_ARRAY, "BPF_MAP_TYPE_PROG_ARRAY", 4, 4, 10},
	{BPF_MAP_TYPE_PERF_EVENT_ARRAY, "BPF_MAP_TYPE_PERF_EVENT_ARRAY", 4, 4, 10},
	{BPF_MAP_TYPE_PERCPU_HASH, "BPF_MAP_TYPE_PERCPU_HASH", 4, 4, 10},
	{BPF_MAP_TYPE_PERCPU_ARRAY, "BPF_MAP_TYPE_PERCPU_ARRAY", 4, 4, 10},
	{BPF_MAP_TYPE_STACK_TRACE, "BPF_MAP_TYPE_STACK_TRACE", 4, 8, 10},
	{BPF_MAP_TYPE_CGROUP_ARRAY, "BPF_MAP_TYPE_CGROUP_ARRAY", 4, 4, 10},
	{BPF_MAP_TYPE_LRU_HASH, "BPF_MAP_TYPE_LRU_HASH", 4, 4, 10},
	{BPF_MAP_TYPE_LRU_PERCPU_HASH, "BPF_MAP_TYPE_LRU_PERCPU_HASH", 4, 4, 10},
	{BPF_MAP_TYPE_LPM_TRIE, "BPF_MAP_TYPE_LPM_TRIE", 32, 4, 10, BPF_F_NO_PREALLOC},
	{BPF_MAP_TYPE_DEVMAP, "BPF_MAP_TYPE_DEVMAP", 4, 4, 10},
	{BPF_MAP_TYPE_SOCKMAP, "BPF_MAP_TYPE_SOCKMAP", 4, 4, 10},
	{BPF_MAP_TYPE_CPUMAP, "BPF_MAP_TYPE_CPUMAP", 4, 4, 10},
	{BPF_MAP_TYPE_XSKMAP, "BPF_MAP_TYPE_XSKMAP", 4, 4, 10},
	{BPF_MAP_TYPE_SOCKHASH, "BPF_MAP_TYPE_SOCKHASH", 4, 4, 10},
	{BPF_MAP_TYPE_REUSEPORT_SOCKARRAY, "BPF_MAP_TYPE_REUSEPORT_SOCKARRAY", 4, 4, 10},
	{BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE, "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE", 8, 4, 0},
	{BPF_MAP_TYPE_QUEUE, "BPF_MAP_TYPE_QUEUE", 0, 4, 10},
	{BPF_MAP_TYPE_DEVMAP_HASH, "BPF_MAP_TYPE_DEVMAP_HASH", 4, 4, 10},
	{BPF_MAP_TYPE_RINGBUF, "BPF_MAP_TYPE_RINGBUF", 0, 0, 4096},
	{BPF_MAP_TYPE_BLOOM_FILTER, "BPF_MAP_TYPE_BLOOM_FILTER", 0, 4, 10},
};

static __u32 flags[] = {
	BPF_F_NO_CHARGE,
};

void test_map_flags(union bpf_attr *attr, char *name)
{
	int mfd;

	mfd = syscall(SYS_bpf, BPF_MAP_CREATE, attr, sizeof(*attr));
	CHECK(mfd <= 0 && mfd != -EPERM, "no_charge", "%s error: %s\n",
		name, strerror(errno));

	if (mfd > 0)
		close(mfd);
}

void test_no_charge(void)
{
	union bpf_attr attr;
	int i, j;

	memset(&attr, 0, sizeof(attr));
	for (i = 0; i < sizeof(flags) / sizeof(__u32); i++) {
		for (j = 0; j < sizeof(attrs) / sizeof(struct map_attr); j++) {
			attr.map_type = attrs[j].map_type;
			attr.key_size = attrs[j].key_size;
			attr.value_size = attrs[j].value_size;
			attr.max_entries = attrs[j].max_entries;
			attr.map_flags = attrs[j].map_flags | flags[i];
			test_map_flags(&attr, attrs[j].map_name);
		}
	}

	printf("%s:PASS\n", __func__);
}
