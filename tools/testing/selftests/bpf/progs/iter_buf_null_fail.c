// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Qi Tang */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} hashmap SEC(".maps");

/*
 * Verify that the verifier rejects direct access to nullable PTR_TO_BUF
 * (ctx->key) without a null check.  On the iterator stop callback,
 * ctx->key is NULL, so unconditional access would be a NULL deref.
 */
SEC("iter/bpf_map_elem")
__failure __msg("invalid mem access")
int iter_buf_null_deref(struct bpf_iter__bpf_map_elem *ctx)
{
	/* ctx->key is PTR_TO_BUF | PTR_MAYBE_NULL | MEM_RDONLY.
	 * Direct access without null check must be rejected.
	 */
	volatile __u32 v = *(__u32 *)ctx->key;

	(void)v;
	return 0;
}

/*
 * Verify that access after a null check is still accepted.
 */
SEC("iter/bpf_map_elem")
__success
int iter_buf_null_check_ok(struct bpf_iter__bpf_map_elem *ctx)
{
	__u32 *key = ctx->key;

	if (!key)
		return 0;

	volatile __u32 v = *key;

	(void)v;
	return 0;
}
