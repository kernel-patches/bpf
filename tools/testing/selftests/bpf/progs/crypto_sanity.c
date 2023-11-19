// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include "bpf_tracing_net.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_kfuncs.h"
#include "crypto_common.h"

#define UDP_TEST_PORT 7777
unsigned char crypto_key[16] = "testtest12345678";
const char crypto_algo[9] = "ecb(aes)";
char dst[32] = {};
int status;

static int skb_dynptr_validate(struct __sk_buff *skb, struct bpf_dynptr *psrc)
{
	struct ipv6hdr ip6h;
	struct udphdr udph;
	u32 offset;

	if (skb->protocol != __bpf_constant_htons(ETH_P_IPV6))
		return -1;

	if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip6h, sizeof(ip6h)))
		return -1;

	if (ip6h.nexthdr != IPPROTO_UDP)
		return -1;

	if (bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(ip6h), &udph, sizeof(udph)))
		return -1;

	if (udph.dest != __bpf_constant_htons(UDP_TEST_PORT))
		return -1;

	offset = ETH_HLEN + sizeof(ip6h) + sizeof(udph);
	if (skb->len < offset + 16)
		return -1;

	bpf_dynptr_from_skb(skb, 0, psrc);
	bpf_dynptr_adjust(psrc, offset, offset + 16);

	return 0;
}

SEC("fentry.s/bpf_fentry_test1")
int BPF_PROG(skb_crypto_setup)
{
	struct bpf_crypto_lskcipher_ctx *cctx;
	struct bpf_dynptr key = {};
	int err = 0;

	status = 0;

	bpf_dynptr_from_mem(crypto_key, sizeof(crypto_key), 0, &key);
	cctx = bpf_crypto_lskcipher_ctx_create(crypto_algo, &key, &err);

	if (!cctx) {
		status = err;
		return 0;
	}

	err = crypto_lskcipher_ctx_insert(cctx);
	if (err && err != -EEXIST)
		status = err;

	return 0;
}

SEC("fentry.s/bpf_fentry_test1")
int BPF_PROG(crypto_release)
{
	struct bpf_crypto_lskcipher_ctx *cctx;
	struct bpf_dynptr key = {};
	int err = 0;

	status = 0;

	bpf_dynptr_from_mem(crypto_key, sizeof(crypto_key), 0, &key);
	cctx = bpf_crypto_lskcipher_ctx_create(crypto_algo, &key, &err);

	if (!cctx) {
		status = err;
		return 0;
	}

	bpf_crypto_lskcipher_ctx_release(cctx);

	return 0;
}

SEC("?fentry.s/bpf_fentry_test1")
__failure __msg("Unreleased reference")
int BPF_PROG(crypto_accuire)
{
	struct bpf_crypto_lskcipher_ctx *cctx;
	struct bpf_dynptr key = {};
	int err = 0;

	status = 0;

	bpf_dynptr_from_mem(crypto_key, sizeof(crypto_key), 0, &key);
	cctx = bpf_crypto_lskcipher_ctx_create(crypto_algo, &key, &err);

	if (!cctx) {
		status = err;
		return 0;
	}

	cctx = bpf_crypto_lskcipher_ctx_acquire(cctx);
	if (!cctx)
		return -EINVAL;

	bpf_crypto_lskcipher_ctx_release(cctx);

	return 0;
}

SEC("tc")
int decrypt_sanity(struct __sk_buff *skb)
{
	struct __crypto_lskcipher_ctx_value *v;
	struct bpf_crypto_lskcipher_ctx *ctx;
	struct bpf_dynptr psrc, pdst, iv;
	int err;

	err = skb_dynptr_validate(skb, &psrc);
	if (err < 0) {
		status = err;
		return TC_ACT_SHOT;
	}

	v = crypto_lskcipher_ctx_value_lookup();
	if (!v) {
		status = -ENOENT;
		return TC_ACT_SHOT;
	}

	ctx = v->ctx;
	if (!ctx) {
		status = -ENOENT;
		return TC_ACT_SHOT;
	}

	bpf_dynptr_from_mem(dst, sizeof(dst), 0, &pdst);
	bpf_dynptr_from_mem(dst, 0, 0, &iv);

	status = bpf_crypto_lskcipher_decrypt(ctx, &psrc, &pdst, &iv);

	return TC_ACT_SHOT;
}

SEC("tc")
int encrypt_sanity(struct __sk_buff *skb)
{
	struct __crypto_lskcipher_ctx_value *v;
	struct bpf_crypto_lskcipher_ctx *ctx;
	struct bpf_dynptr psrc, pdst, iv;
	int err;

	status = 0;

	err = skb_dynptr_validate(skb, &psrc);
	if (err < 0) {
		status = err;
		return TC_ACT_SHOT;
	}

	v = crypto_lskcipher_ctx_value_lookup();
	if (!v) {
		status = -ENOENT;
		return TC_ACT_SHOT;
	}

	ctx = v->ctx;
	if (!ctx) {
		status = -ENOENT;
		return TC_ACT_SHOT;
	}

	bpf_dynptr_from_mem(dst, sizeof(dst), 0, &pdst);
	bpf_dynptr_from_mem(dst, 0, 0, &iv);

	status = bpf_crypto_lskcipher_encrypt(ctx, &psrc, &pdst, &iv);

	return TC_ACT_SHOT;
}

char __license[] SEC("license") = "GPL";
