// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2020 Google LLC.
 */

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, int);
} secure_exec_task_map SEC(".maps");

SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(secure_exec, struct linux_binprm *bprm)
{
	int *secureexec;

	secureexec = bpf_task_storage_get(&secure_exec_task_map,
				   bpf_get_current_task_btf(), 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);

	if (secureexec && *secureexec)
		bpf_lsm_set_bprm_opts(bprm, BPF_LSM_F_BPRM_SECUREEXEC);

	return 0;
}
