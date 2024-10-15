/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#ifndef _UPTR_TEST_COMMON_H
#define _UPTR_TEST_COMMON_H

#define MAGIC_VALUE 0xabcd1234

#ifndef __BPF__
struct cgroup {
	int level;
};
#define __uptr
#define __kptr
#endif

struct user_data {
	int a;
	int b;
	int result;
	int nested_result;
};

struct nested_udata {
	struct user_data __uptr *udata;
};

struct value_type {
	struct user_data __uptr *udata;
	struct cgroup __kptr *cgrp;
	struct nested_udata nested;
};

struct value_lock_type {
	struct user_data __uptr *udata;
	struct bpf_spin_lock lock;
};

#endif
