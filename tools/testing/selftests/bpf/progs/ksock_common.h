/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Isovalent */

#ifndef _KSOCK_COMMON_H
#define _KSOCK_COMMON_H

#include "errno.h"
#include <stdbool.h>

#define SOCK_STREAM	1
#define SOCK_DGRAM	2
#define IPPROTO_TCP	6
#define IPPROTO_UDP	17

struct bpf_ksock *bpf_ksock_create(const struct bpf_ksock_create_opts *opts,
				   u32 opts__sz, int *err__uninit) __ksym;
int bpf_ksock_connect(struct bpf_ksock *ks,
		      const struct bpf_ksock_addr_opts *opts, u32 opts__sz) __ksym;
struct bpf_ksock *bpf_ksock_acquire(struct bpf_ksock *ks) __ksym;
void bpf_ksock_release(struct bpf_ksock *ks) __ksym;
int bpf_ksock_send(struct bpf_ksock *ks,
		   const void *data, u32 data__sz) __ksym;

struct __ksock_ctx_value {
	struct bpf_ksock __kptr * ctx;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct __ksock_ctx_value);
	__uint(max_entries, 1);
} __ksock_ctx_map SEC(".maps");

static inline struct __ksock_ctx_value *ksock_ctx_value_lookup(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&__ksock_ctx_map, &key);
}

static inline int ksock_ctx_insert(struct bpf_ksock *ctx)
{
	struct __ksock_ctx_value *v;
	struct bpf_ksock *old;

	v = ksock_ctx_value_lookup();
	if (!v) {
		bpf_ksock_release(ctx);
		return -ENOENT;
	}

	old = bpf_kptr_xchg(&v->ctx, ctx);
	if (old) {
		bpf_ksock_release(old);
		return -EEXIST;
	}

	return 0;
}

/* Globals for passing config from userspace */
__be32 ipv4_remote;
__u16 remote_port;

char send_data[32] = "hello from bpf ksock";

static inline int do_ksock_setup(void)
{
	struct bpf_ksock_create_opts create_opts = {};
	struct bpf_ksock_addr_opts addr_opts = {};
	struct bpf_ksock *ks;
	int err = 0;

	create_opts.family = AF_INET;
	create_opts.type = SOCK_DGRAM;
	create_opts.protocol = IPPROTO_UDP;

	ks = bpf_ksock_create(&create_opts, sizeof(create_opts), &err);
	if (!ks)
		return err;

	addr_opts.family = AF_INET;
	addr_opts.port = remote_port;
	addr_opts.ipv4_addr = ipv4_remote;

	err = bpf_ksock_connect(ks, &addr_opts, sizeof(addr_opts));
	if (err) {
		bpf_ksock_release(ks);
		return err;
	}

	err = ksock_ctx_insert(ks);
	if (err && err != -EEXIST)
		return err;
	return 0;
}

#endif /* _KSOCK_COMMON_H */
