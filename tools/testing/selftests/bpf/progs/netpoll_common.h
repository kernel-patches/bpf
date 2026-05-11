/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#ifndef _NETPOLL_COMMON_H
#define _NETPOLL_COMMON_H

#include "errno.h"
#include <stdbool.h>

struct bpf_netpoll *bpf_netpoll_create(const struct bpf_netpoll_opts *opts,
				       u32 opts__sz, int *err) __ksym;
struct bpf_netpoll *bpf_netpoll_acquire(struct bpf_netpoll *bnp) __ksym;
void bpf_netpoll_release(struct bpf_netpoll *bnp) __ksym;
int bpf_netpoll_send_udp(struct bpf_netpoll *bnp,
			 const void *data, u32 data__sz) __ksym;

struct __netpoll_ctx_value {
	struct bpf_netpoll __kptr * ctx;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct __netpoll_ctx_value);
	__uint(max_entries, 1);
} __netpoll_ctx_map SEC(".maps");

static inline struct __netpoll_ctx_value *netpoll_ctx_value_lookup(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&__netpoll_ctx_map, &key);
}

static inline int netpoll_ctx_insert(struct bpf_netpoll *ctx)
{
	struct __netpoll_ctx_value local, *v;
	struct bpf_netpoll *old;
	u32 key = 0;
	int err;

	local.ctx = NULL;
	err = bpf_map_update_elem(&__netpoll_ctx_map, &key, &local, 0);
	if (err) {
		bpf_netpoll_release(ctx);
		return err;
	}

	v = bpf_map_lookup_elem(&__netpoll_ctx_map, &key);
	if (!v) {
		bpf_netpoll_release(ctx);
		return -ENOENT;
	}

	old = bpf_kptr_xchg(&v->ctx, ctx);
	if (old) {
		bpf_netpoll_release(old);
		return -EEXIST;
	}

	return 0;
}

#endif /* _NETPOLL_COMMON_H */
