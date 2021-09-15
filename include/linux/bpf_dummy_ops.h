/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021. Huawei Technologies Co., Ltd
 */
#ifndef _BPF_DUMMY_OPS_H
#define _BPF_DUMMY_OPS_H

#ifdef CONFIG_BPF_DUMMY_STRUCT_OPS
#include <linux/module.h>

struct bpf_dummy_ops_state {
	int val;
};

struct bpf_dummy_ops {
	int (*init)(struct bpf_dummy_ops_state *state);
	struct module *owner;
};

extern struct bpf_dummy_ops *bpf_get_dummy_ops(void);
extern void bpf_put_dummy_ops(struct bpf_dummy_ops *ops);
#else
struct bpf_dummy_ops {}；
static inline struct bpf_dummy_ops *bpf_get_dummy_ops(void) { return NULL; }
static inline void bpf_put_dummy_ops(struct bpf_dummy_ops *ops) {}
#endif

#endif
