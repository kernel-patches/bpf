/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#ifndef _CRYPTO_COMMON_H
#define _CRYPTO_COMMON_H

#include "errno.h"
#include <stdbool.h>

#define private(name) SEC(".bss." #name) __hidden __attribute__((aligned(8)))
private(CTX) static struct bpf_crypto_skcipher_ctx __kptr * global_crypto_ctx;

struct bpf_crypto_skcipher_ctx *bpf_crypto_skcipher_ctx_create(const struct bpf_dynptr *algo,
							       const struct bpf_dynptr *key,
							       int *err) __ksym;
struct bpf_crypto_skcipher_ctx *bpf_crypto_skcipher_ctx_acquire(struct bpf_crypto_skcipher_ctx *ctx) __ksym;
void bpf_crypto_skcipher_ctx_release(struct bpf_crypto_skcipher_ctx *ctx) __ksym;
int bpf_crypto_skcipher_encrypt(struct bpf_crypto_skcipher_ctx *ctx,
				const struct bpf_dynptr *src, struct bpf_dynptr *dst,
				const struct bpf_dynptr *iv) __ksym;
int bpf_crypto_skcipher_decrypt(struct bpf_crypto_skcipher_ctx *ctx,
				const struct bpf_dynptr *src, struct bpf_dynptr *dst,
				const struct bpf_dynptr *iv) __ksym;

struct __crypto_skcipher_ctx_value {
	struct bpf_crypto_skcipher_ctx __kptr * ctx;
};

struct crypto_conf_value {
	__u8 algo[32];
	__u32 algo_size;
	__u8 key[32];
	__u32 key_size;
	__u8 iv[32];
	__u32 iv_size;
	__u8 dst[32];
	__u32 dst_size;
};

struct array_conf_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct crypto_conf_value);
	__uint(max_entries, 1);
} __crypto_conf_map SEC(".maps");

struct array_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct __crypto_skcipher_ctx_value);
	__uint(max_entries, 1);
} __crypto_skcipher_ctx_map SEC(".maps");

static inline struct crypto_conf_value *crypto_conf_lookup(void)
{
	struct crypto_conf_value *v, local = {};
	u32 key = 0;

	v = bpf_map_lookup_elem(&__crypto_conf_map, &key);
	if (v)
		return v;

	bpf_map_update_elem(&__crypto_conf_map, &key, &local, 0);
	return bpf_map_lookup_elem(&__crypto_conf_map, &key);
}

static inline struct __crypto_skcipher_ctx_value *crypto_skcipher_ctx_value_lookup(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&__crypto_skcipher_ctx_map, &key);
}

static inline int crypto_skcipher_ctx_insert(struct bpf_crypto_skcipher_ctx *ctx)
{
	struct __crypto_skcipher_ctx_value local, *v;
	long status;
	struct bpf_crypto_skcipher_ctx *old;
	u32 key = 0;

	local.ctx = NULL;
	status = bpf_map_update_elem(&__crypto_skcipher_ctx_map, &key, &local, 0);
	if (status) {
		bpf_crypto_skcipher_ctx_release(ctx);
		return status;
	}

	v = bpf_map_lookup_elem(&__crypto_skcipher_ctx_map, &key);
	if (!v) {
		bpf_crypto_skcipher_ctx_release(ctx);
		return -ENOENT;
	}

	old = bpf_kptr_xchg(&v->ctx, ctx);
	if (old) {
		bpf_crypto_skcipher_ctx_release(old);
		return -EEXIST;
	}

	return 0;
}

#endif /* _CRYPTO_COMMON_H */
