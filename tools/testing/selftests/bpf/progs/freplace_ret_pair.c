// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * An extension replaces its target outright, so it has to match the target's
 * return convention. Its own return value is capped at 8 bytes, so it can
 * never fill the R0:R2 pair that the target's callers read, and the attach is
 * rejected. btf_check_type_match() cannot catch this: it compares return types
 * by btf_type->info only, and an int carries no vlen, so the __u64 here and
 * the target's __int128 compare equal.
 */
SEC("freplace/agg_ret_target_func")
__u64 new_agg_ret_target_func(void)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
