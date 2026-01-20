/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#ifndef _BPF_CRYPTO_H
#define _BPF_CRYPTO_H

enum bpf_crypto_type_id {
	BPF_CRYPTO_TYPE_SKCIPHER = 1,
	BPF_CRYPTO_TYPE_HASH,
	BPF_CRYPTO_TYPE_SIG,
};

struct bpf_crypto_type {
	void *(*alloc_tfm)(const char *algo);
	void (*free_tfm)(void *tfm);
	int (*has_algo)(const char *algo);
	int (*setkey)(void *tfm, const u8 *key, unsigned int keylen);
	int (*setauthsize)(void *tfm, unsigned int authsize);
	int (*encrypt)(void *tfm, const u8 *src, u8 *dst, unsigned int len, u8 *iv);
	int (*decrypt)(void *tfm, const u8 *src, u8 *dst, unsigned int len, u8 *iv);
	int (*hash)(void *tfm, const u8 *data, u8 *out, unsigned int len);
	int (*verify)(void *tfm, const u8 *sig, unsigned int sig_len,
		      const u8 *msg, unsigned int msg_len);
	unsigned int (*ivsize)(void *tfm);
	unsigned int (*statesize)(void *tfm);
	unsigned int (*digestsize)(void *tfm);
	unsigned int (*keysize)(void *tfm);
	unsigned int (*maxsize)(void *tfm);
	u32 (*get_flags)(void *tfm);
	struct module *owner;
	enum bpf_crypto_type_id type_id;
	char name[14];
};

int bpf_crypto_register_type(const struct bpf_crypto_type *type);
int bpf_crypto_unregister_type(const struct bpf_crypto_type *type);

#endif /* _BPF_CRYPTO_H */
