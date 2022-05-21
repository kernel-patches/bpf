/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1000);
	__type(key, int);
	__type(value, int);
} array_of_maps SEC(".maps");

long important_hits;
long hits;

#ifdef LOOKUP_HASHMAP
static int do_lookup(unsigned int elem, struct task_struct *task /* unused */)
{
	void *map;
	int zero = 0;

	map = bpf_map_lookup_elem(&array_of_maps, &elem);
	if (!map)
		return -1;

	bpf_map_lookup_elem(map, &zero);
	__sync_add_and_fetch(&hits, 1);
	if (!elem)
		__sync_add_and_fetch(&important_hits, 1);
	return 0;
}
#else
static int do_lookup(unsigned int elem, struct task_struct *task)
{
	void *map;

	map = bpf_map_lookup_elem(&array_of_maps, &elem);
	if (!map)
		return -1;

	bpf_task_storage_get(map, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	__sync_add_and_fetch(&hits, 1);
	if (!elem)
		__sync_add_and_fetch(&important_hits, 1);
	return 0;
}
#endif /* LOOKUP_HASHMAP */

#define TASK_STORAGE_GET_LOOP_PROG(interleave)			\
SEC("fentry/" SYS_PREFIX "sys_getpgid")			\
int get_local(void *ctx)					\
{								\
	struct task_struct *task;				\
	unsigned int i;						\
	void *map;						\
								\
	task = bpf_get_current_task_btf();			\
	for (i = 0; i < 1000; i++) {				\
		if (do_lookup(i, task))				\
			return 0;				\
		if (interleave && i % 3 == 0)			\
			do_lookup(0, task);			\
	}							\
	return 0;						\
}
