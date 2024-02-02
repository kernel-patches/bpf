/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2020 Facebook */
#ifndef _BPF_TESTMOD_H
#define _BPF_TESTMOD_H

#include <linux/types.h>

struct task_struct;

struct bpf_testmod_test_read_ctx {
	char *buf;
	loff_t off;
	size_t len;
};

struct bpf_testmod_test_write_ctx {
	char *buf;
	loff_t off;
	size_t len;
};

struct bpf_testmod_test_writable_ctx {
	bool early_ret;
	int val;
};

/* BPF iter that returns *value* *n* times in a row */
struct bpf_iter_testmod_seq {
	s64 value;
	int cnt;
};

typedef u32 (*ar_t)[2];
typedef u32 (*ar2_t)[];

struct bpf_testmod_ops {
	int (*test_1)(void);
	int (*test_2)(int a, int b);
	/* Used to test nullable arguments. */
	int (*test_maybe_null)(int dummy, struct task_struct *task,
			       u32 *scalar,
			       ar_t ar,
			       ar2_t ar2);
};

#endif /* _BPF_TESTMOD_H */
