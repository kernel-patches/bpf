// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2025 David Windsor.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define DUMMY_STORAGE_VALUE 0xdeadbeef

extern struct bpf_local_storage_data *bpf_cred_storage_get(struct bpf_map *map,
							   struct cred *cred,
							   void *init, int init__sz, __u64 flags) __ksym;

__u32 monitored_pid = 0;
int cred_storage_result = -1;

struct cred_storage {
	__u32 value;
};

struct {
	__uint(type, BPF_MAP_TYPE_CRED_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cred_storage);
} cred_storage_map SEC(".maps");

SEC("lsm/cred_prepare")
int BPF_PROG(cred_prepare, struct cred *new, const struct cred *old, gfp_t gfp)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct cred_storage init_storage = {
		.value = DUMMY_STORAGE_VALUE,
	};
	struct bpf_local_storage_data *sdata;
	struct cred_storage *storage;

	if (pid != monitored_pid)
		return 0;

	sdata = bpf_cred_storage_get((struct bpf_map *)&cred_storage_map, new, &init_storage,
				     sizeof(init_storage), BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!sdata)
		return 0;

	storage = (struct cred_storage *)sdata->data;
	if (!storage)
		return 0;

	/* Verify the storage was initialized correctly */
	if (storage->value == DUMMY_STORAGE_VALUE)
		cred_storage_result = 0;

	return 0;
}

SEC("lsm/cred_free")
int BPF_PROG(cred_free, struct cred *cred)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct bpf_local_storage_data *sdata;
	struct cred_storage *storage;

	if (pid != monitored_pid)
		return 0;

	/* Try to retrieve the storage that should have been created in prepare */
	sdata = bpf_cred_storage_get((struct bpf_map *)&cred_storage_map, cred,
				     NULL, 0, 0);
	if (!sdata)
		return 0;

	storage = (struct cred_storage *)sdata->data;
	if (!storage)
		return 0;

	/* Verify the dummy value is still there during free */
	if (storage->value == DUMMY_STORAGE_VALUE)
		cred_storage_result = 0;

	return 0;
}
