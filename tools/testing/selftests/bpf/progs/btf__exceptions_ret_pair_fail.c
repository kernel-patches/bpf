// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

unsigned __int128 exception_cb_bad_ret_type3(u64 cookie)
{
	for (;;)
		;
}
