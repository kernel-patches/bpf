// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright 2021 Google LLC.
 */

#include <errno.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

__u32 invocations = 0;
__u32 assertion_error = 0;
__u32 errno_value = 0;

SEC("cgroup/setsockopt")
int get_errno(struct bpf_sockopt *ctx)
{
	errno_value = bpf_export_errno(0);
	__sync_fetch_and_add(&invocations, 1);

	return 1;
}

SEC("cgroup/setsockopt")
int set_eunatch(struct bpf_sockopt *ctx)
{
	__sync_fetch_and_add(&invocations, 1);

	if (bpf_export_errno(EUNATCH))
		assertion_error = 1;

	return 0;
}

SEC("cgroup/setsockopt")
int set_eisconn(struct bpf_sockopt *ctx)
{
	__sync_fetch_and_add(&invocations, 1);

	if (bpf_export_errno(EISCONN))
		assertion_error = 1;

	return 0;
}

SEC("cgroup/setsockopt")
int legacy_eperm(struct bpf_sockopt *ctx)
{
	__sync_fetch_and_add(&invocations, 1);

	return 0;
}
