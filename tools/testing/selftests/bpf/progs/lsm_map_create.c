// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

char _license[] SEC("license") = "GPL";

int my_tid;
/* LSM enforcement:
 *   - 0, delegate to kernel;
 *   - 1, allow;
 *   - -1, reject.
 */
int decision;

SEC("lsm/bpf_map_create_security")
int BPF_PROG(allow_unpriv_maps, union bpf_attr *attr)
{
	if (!my_tid || (u32)bpf_get_current_pid_tgid() != my_tid)
		return 0; /* keep processing LSM hooks */

	if (decision == 0)
		return 0;

	if (decision > 0)
		return 1; /* allow */

	return -EPERM;
}

SEC("lsm/bpf_btf_load_security")
int BPF_PROG(allow_unpriv_btf, union bpf_attr *attr)
{
	if (!my_tid || (u32)bpf_get_current_pid_tgid() != my_tid)
		return 0; /* keep processing LSM hooks */

	if (decision == 0)
		return 0;

	if (decision > 0)
		return 1; /* allow */

	return -EPERM;
}
