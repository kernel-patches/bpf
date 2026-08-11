// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

unsigned __int128 timer_cb_ret_pair(void *map, int *key, struct bpf_timer *timer)
{
	for (;;)
		;
}
