// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024 Meta, Inc */
#include <linux/bpf.h>
#include <linux/bpf_crypto.h>
#include <linux/bpf_mem_alloc.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/scatterlist.h>
#include <linux/skbuff.h>
#include <crypto/skcipher.h>
#include <crypto/sha2.h>
#include <crypto/sig.h>

struct bpf_crypto_type_list {
	const struct bpf_crypto_type *type;
	struct list_head list;
};

/* BPF crypto initialization parameters struct */
/**
 * struct bpf_crypto_params - BPF crypto initialization parameters structure
 * @type:	The string of crypto operation type.
 * @reserved:	Reserved member, will be reused for more options in future
 *		Values:
 *		  0
 * @algo:	The string of algorithm to initialize.
 * @key:	The cipher key used to init crypto algorithm.
 * @key_len:	The length of cipher key.
 * @authsize:	The length of authentication tag used by algorithm.
 */
struct bpf_crypto_params {
	char type[14];
	u8 reserved[2];
	char algo[128];
	u8 key[256];
	u32 key_len;
	u32 authsize;
};

static LIST_HEAD(bpf_crypto_types);
static DECLARE_RWSEM(bpf_crypto_types_sem);

/**
 * struct bpf_crypto_ctx - refcounted BPF crypto context structure
 * @type:	The pointer to bpf crypto type
 * @tfm:	The pointer to instance of crypto API struct.
 * @siv_len:    Size of IV and state storage for cipher
 * @rcu:	The RCU head used to free the crypto context with RCU safety.
 * @usage:	Object reference counter. When the refcount goes to 0, the
 *		memory is released back to the BPF allocator, which provides
 *		RCU safety.
 */
struct bpf_crypto_ctx {
	const struct bpf_crypto_type *type;
	void *tfm;
	u32 siv_len;
	struct rcu_head rcu;
	refcount_t usage;
};

#if IS_ENABLED(CONFIG_CRYPTO_ECDSA)
/**
 * struct bpf_ecdsa_ctx - refcounted BPF ECDSA context structure
 * @tfm:	The crypto_sig transform for ECDSA operations
 * @rcu:	The RCU head used to free the context with RCU safety
 * @usage:	Object reference counter. When the refcount goes to 0, the
 *		memory is released with RCU safety.
 */
struct bpf_ecdsa_ctx {
	struct crypto_sig *tfm;
	struct rcu_head rcu;
	refcount_t usage;
};
#endif

int bpf_crypto_register_type(const struct bpf_crypto_type *type)
{
	struct bpf_crypto_type_list *node;
	int err = -EEXIST;

	down_write(&bpf_crypto_types_sem);
	list_for_each_entry(node, &bpf_crypto_types, list) {
		if (!strcmp(node->type->name, type->name))
			goto unlock;
	}

	node = kmalloc(sizeof(*node), GFP_KERNEL);
	err = -ENOMEM;
	if (!node)
		goto unlock;

	node->type = type;
	list_add(&node->list, &bpf_crypto_types);
	err = 0;

unlock:
	up_write(&bpf_crypto_types_sem);

	return err;
}
EXPORT_SYMBOL_GPL(bpf_crypto_register_type);

int bpf_crypto_unregister_type(const struct bpf_crypto_type *type)
{
	struct bpf_crypto_type_list *node;
	int err = -ENOENT;

	down_write(&bpf_crypto_types_sem);
	list_for_each_entry(node, &bpf_crypto_types, list) {
		if (strcmp(node->type->name, type->name))
			continue;

		list_del(&node->list);
		kfree(node);
		err = 0;
		break;
	}
	up_write(&bpf_crypto_types_sem);

	return err;
}
EXPORT_SYMBOL_GPL(bpf_crypto_unregister_type);

static const struct bpf_crypto_type *bpf_crypto_get_type(const char *name)
{
	const struct bpf_crypto_type *type = ERR_PTR(-ENOENT);
	struct bpf_crypto_type_list *node;

	down_read(&bpf_crypto_types_sem);
	list_for_each_entry(node, &bpf_crypto_types, list) {
		if (strcmp(node->type->name, name))
			continue;

		if (try_module_get(node->type->owner))
			type = node->type;
		break;
	}
	up_read(&bpf_crypto_types_sem);

	return type;
}

__bpf_kfunc_start_defs();

/**
 * bpf_crypto_ctx_create() - Create a mutable BPF crypto context.
 *
 * Allocates a crypto context that can be used, acquired, and released by
 * a BPF program. The crypto context returned by this function must either
 * be embedded in a map as a kptr, or freed with bpf_crypto_ctx_release().
 * As crypto API functions use GFP_KERNEL allocations, this function can
 * only be used in sleepable BPF programs.
 *
 * bpf_crypto_ctx_create() allocates memory for crypto context.
 * It may return NULL if no memory is available.
 * @params:	pointer to struct bpf_crypto_params which contains all the
 *		details needed to initialise crypto context.
 * @params__sz:	size of steuct bpf_crypto_params usef by bpf program
 * @err:	integer to store error code when NULL is returned.
 */
__bpf_kfunc struct bpf_crypto_ctx *
bpf_crypto_ctx_create(const struct bpf_crypto_params *params, u32 params__sz,
		      int *err)
{
	const struct bpf_crypto_type *type;
	struct bpf_crypto_ctx *ctx;

	if (!params || params->reserved[0] || params->reserved[1] ||
	    params__sz != sizeof(struct bpf_crypto_params)) {
		*err = -EINVAL;
		return NULL;
	}

	type = bpf_crypto_get_type(params->type);
	if (IS_ERR(type)) {
		*err = PTR_ERR(type);
		return NULL;
	}

	if (!type->has_algo(params->algo)) {
		*err = -EOPNOTSUPP;
		goto err_module_put;
	}

	if (!!params->authsize ^ !!type->setauthsize) {
		*err = -EOPNOTSUPP;
		goto err_module_put;
	}

	if (!params->key_len || params->key_len > sizeof(params->key)) {
		*err = -EINVAL;
		goto err_module_put;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		*err = -ENOMEM;
		goto err_module_put;
	}

	ctx->type = type;
	ctx->tfm = type->alloc_tfm(params->algo);
	if (IS_ERR(ctx->tfm)) {
		*err = PTR_ERR(ctx->tfm);
		goto err_free_ctx;
	}

	if (params->authsize) {
		*err = type->setauthsize(ctx->tfm, params->authsize);
		if (*err)
			goto err_free_tfm;
	}

	*err = type->setkey(ctx->tfm, params->key, params->key_len);
	if (*err)
		goto err_free_tfm;

	if (type->get_flags(ctx->tfm) & CRYPTO_TFM_NEED_KEY) {
		*err = -EINVAL;
		goto err_free_tfm;
	}

	ctx->siv_len = type->ivsize(ctx->tfm) + type->statesize(ctx->tfm);

	refcount_set(&ctx->usage, 1);

	return ctx;

err_free_tfm:
	type->free_tfm(ctx->tfm);
err_free_ctx:
	kfree(ctx);
err_module_put:
	module_put(type->owner);

	return NULL;
}

static void crypto_free_cb(struct rcu_head *head)
{
	struct bpf_crypto_ctx *ctx;

	ctx = container_of(head, struct bpf_crypto_ctx, rcu);
	ctx->type->free_tfm(ctx->tfm);
	module_put(ctx->type->owner);
	kfree(ctx);
}

/**
 * bpf_crypto_ctx_acquire() - Acquire a reference to a BPF crypto context.
 * @ctx: The BPF crypto context being acquired. The ctx must be a trusted
 *	     pointer.
 *
 * Acquires a reference to a BPF crypto context. The context returned by this function
 * must either be embedded in a map as a kptr, or freed with
 * bpf_crypto_ctx_release().
 */
__bpf_kfunc struct bpf_crypto_ctx *
bpf_crypto_ctx_acquire(struct bpf_crypto_ctx *ctx)
{
	if (!refcount_inc_not_zero(&ctx->usage))
		return NULL;
	return ctx;
}

/**
 * bpf_crypto_ctx_release() - Release a previously acquired BPF crypto context.
 * @ctx: The crypto context being released.
 *
 * Releases a previously acquired reference to a BPF crypto context. When the final
 * reference of the BPF crypto context has been released, its memory
 * will be released.
 */
__bpf_kfunc void bpf_crypto_ctx_release(struct bpf_crypto_ctx *ctx)
{
	if (refcount_dec_and_test(&ctx->usage))
		call_rcu(&ctx->rcu, crypto_free_cb);
}

static int bpf_crypto_crypt(const struct bpf_crypto_ctx *ctx,
			    const struct bpf_dynptr_kern *src,
			    const struct bpf_dynptr_kern *dst,
			    const struct bpf_dynptr_kern *siv,
			    bool decrypt)
{
	u32 src_len, dst_len, siv_len;
	const u8 *psrc;
	u8 *pdst, *piv;
	int err;

	if (__bpf_dynptr_is_rdonly(dst))
		return -EINVAL;

	siv_len = siv ? __bpf_dynptr_size(siv) : 0;
	src_len = __bpf_dynptr_size(src);
	dst_len = __bpf_dynptr_size(dst);
	if (!src_len || !dst_len || src_len > dst_len)
		return -EINVAL;

	if (siv_len != ctx->siv_len)
		return -EINVAL;

	psrc = __bpf_dynptr_data(src, src_len);
	if (!psrc)
		return -EINVAL;
	pdst = __bpf_dynptr_data_rw(dst, dst_len);
	if (!pdst)
		return -EINVAL;

	piv = siv_len ? __bpf_dynptr_data_rw(siv, siv_len) : NULL;
	if (siv_len && !piv)
		return -EINVAL;

	err = decrypt ? ctx->type->decrypt(ctx->tfm, psrc, pdst, src_len, piv)
		      : ctx->type->encrypt(ctx->tfm, psrc, pdst, src_len, piv);

	return err;
}

/**
 * bpf_crypto_decrypt() - Decrypt buffer using configured context and IV provided.
 * @ctx:		The crypto context being used. The ctx must be a trusted pointer.
 * @src:		bpf_dynptr to the encrypted data. Must be a trusted pointer.
 * @dst:		bpf_dynptr to the buffer where to store the result. Must be a trusted pointer.
 * @siv__nullable:	bpf_dynptr to IV data and state data to be used by decryptor. May be NULL.
 *
 * Decrypts provided buffer using IV data and the crypto context. Crypto context must be configured.
 */
__bpf_kfunc int bpf_crypto_decrypt(struct bpf_crypto_ctx *ctx,
				   const struct bpf_dynptr *src,
				   const struct bpf_dynptr *dst,
				   const struct bpf_dynptr *siv__nullable)
{
	const struct bpf_dynptr_kern *src_kern = (struct bpf_dynptr_kern *)src;
	const struct bpf_dynptr_kern *dst_kern = (struct bpf_dynptr_kern *)dst;
	const struct bpf_dynptr_kern *siv_kern = (struct bpf_dynptr_kern *)siv__nullable;

	return bpf_crypto_crypt(ctx, src_kern, dst_kern, siv_kern, true);
}

/**
 * bpf_crypto_encrypt() - Encrypt buffer using configured context and IV provided.
 * @ctx:		The crypto context being used. The ctx must be a trusted pointer.
 * @src:		bpf_dynptr to the plain data. Must be a trusted pointer.
 * @dst:		bpf_dynptr to the buffer where to store the result. Must be a trusted pointer.
 * @siv__nullable:	bpf_dynptr to IV data and state data to be used by decryptor. May be NULL.
 *
 * Encrypts provided buffer using IV data and the crypto context. Crypto context must be configured.
 */
__bpf_kfunc int bpf_crypto_encrypt(struct bpf_crypto_ctx *ctx,
				   const struct bpf_dynptr *src,
				   const struct bpf_dynptr *dst,
				   const struct bpf_dynptr *siv__nullable)
{
	const struct bpf_dynptr_kern *src_kern = (struct bpf_dynptr_kern *)src;
	const struct bpf_dynptr_kern *dst_kern = (struct bpf_dynptr_kern *)dst;
	const struct bpf_dynptr_kern *siv_kern = (struct bpf_dynptr_kern *)siv__nullable;

	return bpf_crypto_crypt(ctx, src_kern, dst_kern, siv_kern, false);
}

#if IS_ENABLED(CONFIG_CRYPTO_LIB_SHA256)
/**
 * bpf_sha256_hash() - Compute SHA-256 hash using kernel crypto library
 * @data: bpf_dynptr to the input data to hash. Must be a trusted pointer.
 * @out: bpf_dynptr to the output buffer (must be at least 32 bytes). Must be a trusted pointer.
 *
 * Computes SHA-256 hash of the input data. Uses bpf_dynptr to ensure safe memory access
 * without risk of page faults.
 */
__bpf_kfunc int bpf_sha256_hash(const struct bpf_dynptr *data, const struct bpf_dynptr *out)
{
	const struct bpf_dynptr_kern *data_kern = (struct bpf_dynptr_kern *)data;
	const struct bpf_dynptr_kern *out_kern = (struct bpf_dynptr_kern *)out;
	u32 data_len, out_len;
	const u8 *data_ptr;
	u8 *out_ptr;

	if (__bpf_dynptr_is_rdonly(out_kern))
		return -EINVAL;

	data_len = __bpf_dynptr_size(data_kern);
	out_len = __bpf_dynptr_size(out_kern);

	if (data_len == 0 || out_len < 32)
		return -EINVAL;

	data_ptr = __bpf_dynptr_data(data_kern, data_len);
	if (!data_ptr)
		return -EINVAL;

	out_ptr = __bpf_dynptr_data_rw(out_kern, out_len);
	if (!out_ptr)
		return -EINVAL;

	sha256(data_ptr, data_len, out_ptr);

	return 0;
}

/**
 * bpf_sha384_hash() - Compute SHA-384 hash using kernel crypto library
 * @data: bpf_dynptr to the input data to hash. Must be a trusted pointer.
 * @out: bpf_dynptr to the output buffer (must be at least 48 bytes). Must be a trusted pointer.
 *
 * Computes SHA-384 hash of the input data. Uses bpf_dynptr to ensure safe memory access
 * without risk of page faults.
 */
__bpf_kfunc int bpf_sha384_hash(const struct bpf_dynptr *data, const struct bpf_dynptr *out)
{
	const struct bpf_dynptr_kern *data_kern = (struct bpf_dynptr_kern *)data;
	const struct bpf_dynptr_kern *out_kern = (struct bpf_dynptr_kern *)out;
	u32 data_len, out_len;
	const u8 *data_ptr;
	u8 *out_ptr;

	if (__bpf_dynptr_is_rdonly(out_kern))
		return -EINVAL;

	data_len = __bpf_dynptr_size(data_kern);
	out_len = __bpf_dynptr_size(out_kern);

	if (data_len == 0 || out_len < 48)
		return -EINVAL;

	data_ptr = __bpf_dynptr_data(data_kern, data_len);
	if (!data_ptr)
		return -EINVAL;

	out_ptr = __bpf_dynptr_data_rw(out_kern, out_len);
	if (!out_ptr)
		return -EINVAL;

	sha384(data_ptr, data_len, out_ptr);

	return 0;
}

/**
 * bpf_sha512_hash() - Compute SHA-512 hash using kernel crypto library
 * @data: bpf_dynptr to the input data to hash. Must be a trusted pointer.
 * @out: bpf_dynptr to the output buffer (must be at least 64 bytes). Must be a trusted pointer.
 *
 * Computes SHA-512 hash of the input data. Uses bpf_dynptr to ensure safe memory access
 * without risk of page faults.
 */
__bpf_kfunc int bpf_sha512_hash(const struct bpf_dynptr *data, const struct bpf_dynptr *out)
{
	const struct bpf_dynptr_kern *data_kern = (struct bpf_dynptr_kern *)data;
	const struct bpf_dynptr_kern *out_kern = (struct bpf_dynptr_kern *)out;
	u32 data_len, out_len;
	const u8 *data_ptr;
	u8 *out_ptr;

	if (__bpf_dynptr_is_rdonly(out_kern))
		return -EINVAL;

	data_len = __bpf_dynptr_size(data_kern);
	out_len = __bpf_dynptr_size(out_kern);

	if (data_len == 0 || out_len < 64)
		return -EINVAL;

	data_ptr = __bpf_dynptr_data(data_kern, data_len);
	if (!data_ptr)
		return -EINVAL;

	out_ptr = __bpf_dynptr_data_rw(out_kern, out_len);
	if (!out_ptr)
		return -EINVAL;

	sha512(data_ptr, data_len, out_ptr);

	return 0;
}
#endif /* CONFIG_CRYPTO_LIB_SHA256 */

#if IS_ENABLED(CONFIG_CRYPTO_ECDSA)
/**
 * bpf_ecdsa_ctx_create() - Create a BPF ECDSA verification context
 * @algo_name: bpf_dynptr to the algorithm name (e.g., "p1363(ecdsa-nist-p256)")
 * @public_key: bpf_dynptr to the public key in uncompressed format (0x04 || x || y)
 *              Must be 65 bytes for P-256, 97 for P-384, 133 for P-521
 * @err: Pointer to store error code on failure
 *
 * Creates an ECDSA verification context that can be reused for multiple
 * signature verifications. This function uses GFP_KERNEL allocation and
 * can only be called from sleepable BPF programs. Uses bpf_dynptr to ensure
 * safe memory access without risk of page faults.
 */
__bpf_kfunc struct bpf_ecdsa_ctx *
bpf_ecdsa_ctx_create(const struct bpf_dynptr *algo_name,
		     const struct bpf_dynptr *public_key, int *err)
{
	const struct bpf_dynptr_kern *algo_kern = (struct bpf_dynptr_kern *)algo_name;
	const struct bpf_dynptr_kern *key_kern = (struct bpf_dynptr_kern *)public_key;
	struct bpf_ecdsa_ctx *ctx;
	const char *algo_ptr;
	const u8 *key_ptr;
	u32 algo_len, key_len;
	char algo[64];
	int ret;

	if (!err)
		return NULL;

	algo_len = __bpf_dynptr_size(algo_kern);
	key_len = __bpf_dynptr_size(key_kern);

	if (algo_len == 0 || algo_len >= sizeof(algo)) {
		*err = -EINVAL;
		return NULL;
	}

	if (key_len < 65) {
		*err = -EINVAL;
		return NULL;
	}

	algo_ptr = __bpf_dynptr_data(algo_kern, algo_len);
	if (!algo_ptr) {
		*err = -EINVAL;
		return NULL;
	}

	key_ptr = __bpf_dynptr_data(key_kern, key_len);
	if (!key_ptr) {
		*err = -EINVAL;
		return NULL;
	}

	if (key_ptr[0] != 0x04) {
		*err = -EINVAL;
		return NULL;
	}

	memcpy(algo, algo_ptr, algo_len);
	algo[algo_len] = '\0';

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		*err = -ENOMEM;
		return NULL;
	}

	ctx->tfm = crypto_alloc_sig(algo, 0, 0);
	if (IS_ERR(ctx->tfm)) {
		*err = PTR_ERR(ctx->tfm);
		kfree(ctx);
		return NULL;
	}

	ret = crypto_sig_set_pubkey(ctx->tfm, key_ptr, key_len);
	if (ret) {
		*err = ret;
		crypto_free_sig(ctx->tfm);
		kfree(ctx);
		return NULL;
	}

	refcount_set(&ctx->usage, 1);
	*err = 0;
	return ctx;
}

/**
 * bpf_ecdsa_verify() - Verify ECDSA signature using pre-allocated context
 * @ctx: ECDSA context created by bpf_ecdsa_ctx_create()
 * @message: bpf_dynptr to the message hash to verify. Must be a trusted pointer.
 * @signature: bpf_dynptr to the ECDSA signature in r || s format. Must be a trusted pointer.
 *             Must be 64 bytes for P-256, 96 for P-384, 132 for P-521
 *
 * Verifies an ECDSA signature using a pre-allocated context. This function
 * does not allocate memory and can be used in non-sleepable BPF programs.
 * Uses bpf_dynptr to ensure safe memory access without risk of page faults.
 */
__bpf_kfunc int bpf_ecdsa_verify(struct bpf_ecdsa_ctx *ctx,
				 const struct bpf_dynptr *message,
				 const struct bpf_dynptr *signature)
{
	const struct bpf_dynptr_kern *msg_kern = (struct bpf_dynptr_kern *)message;
	const struct bpf_dynptr_kern *sig_kern = (struct bpf_dynptr_kern *)signature;
	const u8 *msg_ptr, *sig_ptr;
	u32 msg_len, sig_len;

	if (!ctx)
		return -EINVAL;

	msg_len = __bpf_dynptr_size(msg_kern);
	sig_len = __bpf_dynptr_size(sig_kern);

	if (msg_len == 0 || sig_len == 0)
		return -EINVAL;

	msg_ptr = __bpf_dynptr_data(msg_kern, msg_len);
	if (!msg_ptr)
		return -EINVAL;

	sig_ptr = __bpf_dynptr_data(sig_kern, sig_len);
	if (!sig_ptr)
		return -EINVAL;

	return crypto_sig_verify(ctx->tfm, sig_ptr, sig_len, msg_ptr, msg_len);
}

__bpf_kfunc struct bpf_ecdsa_ctx *
bpf_ecdsa_ctx_acquire(struct bpf_ecdsa_ctx *ctx)
{
	if (!refcount_inc_not_zero(&ctx->usage))
		return NULL;
	return ctx;
}

static void ecdsa_free_cb(struct rcu_head *head)
{
	struct bpf_ecdsa_ctx *ctx = container_of(head, struct bpf_ecdsa_ctx, rcu);

	crypto_free_sig(ctx->tfm);
	kfree(ctx);
}

__bpf_kfunc void bpf_ecdsa_ctx_release(struct bpf_ecdsa_ctx *ctx)
{
	if (refcount_dec_and_test(&ctx->usage))
		call_rcu(&ctx->rcu, ecdsa_free_cb);
}

/**
 * bpf_ecdsa_ctx_create_with_privkey() - Create a BPF ECDSA signing context
 * @algo_name: bpf_dynptr to the algorithm name (e.g., "p1363(ecdsa-nist-p256)")
 * @private_key: bpf_dynptr to the private key in raw format
 * @err: Pointer to store error code on failure
 *
 * Creates an ECDSA signing context that can be used for signing messages.
 * This function uses GFP_KERNEL allocation and can only be called from
 * sleepable BPF programs. Uses bpf_dynptr to ensure safe memory access
 * without risk of page faults.
 */
__bpf_kfunc struct bpf_ecdsa_ctx *
bpf_ecdsa_ctx_create_with_privkey(const struct bpf_dynptr *algo_name,
				   const struct bpf_dynptr *private_key, int *err)
{
	const struct bpf_dynptr_kern *algo_kern = (struct bpf_dynptr_kern *)algo_name;
	const struct bpf_dynptr_kern *key_kern = (struct bpf_dynptr_kern *)private_key;
	struct bpf_ecdsa_ctx *ctx;
	const char *algo_ptr;
	const u8 *key_ptr;
	u32 algo_len, key_len;
	char algo[64];
	int ret;

	if (!err)
		return NULL;

	algo_len = __bpf_dynptr_size(algo_kern);
	key_len = __bpf_dynptr_size(key_kern);

	if (algo_len == 0 || algo_len >= sizeof(algo)) {
		*err = -EINVAL;
		return NULL;
	}

	if (key_len < 32) {
		*err = -EINVAL;
		return NULL;
	}

	algo_ptr = __bpf_dynptr_data(algo_kern, algo_len);
	if (!algo_ptr) {
		*err = -EINVAL;
		return NULL;
	}

	key_ptr = __bpf_dynptr_data(key_kern, key_len);
	if (!key_ptr) {
		*err = -EINVAL;
		return NULL;
	}

	memcpy(algo, algo_ptr, algo_len);
	algo[algo_len] = '\0';

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		*err = -ENOMEM;
		return NULL;
	}

	ctx->tfm = crypto_alloc_sig(algo, 0, 0);
	if (IS_ERR(ctx->tfm)) {
		*err = PTR_ERR(ctx->tfm);
		kfree(ctx);
		return NULL;
	}

	ret = crypto_sig_set_privkey(ctx->tfm, key_ptr, key_len);
	if (ret) {
		*err = ret;
		crypto_free_sig(ctx->tfm);
		kfree(ctx);
		return NULL;
	}

	refcount_set(&ctx->usage, 1);
	*err = 0;
	return ctx;
}

/**
 * bpf_ecdsa_sign() - Sign a message using ECDSA
 * @ctx: ECDSA context created with bpf_ecdsa_ctx_create_with_privkey()
 * @message: bpf_dynptr to the message hash to sign. Must be a trusted pointer.
 * @signature: bpf_dynptr to the output buffer for signature. Must be a trusted pointer.
 *             Must be at least 64 bytes for P-256, 96 for P-384, 132 for P-521
 *
 * Signs a message hash using ECDSA with a pre-configured private key.
 * The signature is returned in r || s format. Uses bpf_dynptr to ensure
 * safe memory access without risk of page faults.
 */
__bpf_kfunc int bpf_ecdsa_sign(struct bpf_ecdsa_ctx *ctx,
			       const struct bpf_dynptr *message,
			       const struct bpf_dynptr *signature)
{
	const struct bpf_dynptr_kern *msg_kern = (struct bpf_dynptr_kern *)message;
	const struct bpf_dynptr_kern *sig_kern = (struct bpf_dynptr_kern *)signature;
	const u8 *msg_ptr;
	u8 *sig_ptr;
	u32 msg_len, sig_len;

	if (!ctx)
		return -EINVAL;

	if (__bpf_dynptr_is_rdonly(sig_kern))
		return -EINVAL;

	msg_len = __bpf_dynptr_size(msg_kern);
	sig_len = __bpf_dynptr_size(sig_kern);

	if (msg_len == 0 || sig_len == 0)
		return -EINVAL;

	msg_ptr = __bpf_dynptr_data(msg_kern, msg_len);
	if (!msg_ptr)
		return -EINVAL;

	sig_ptr = __bpf_dynptr_data_rw(sig_kern, sig_len);
	if (!sig_ptr)
		return -EINVAL;

	return crypto_sig_sign(ctx->tfm, msg_ptr, msg_len, sig_ptr, sig_len);
}

/**
 * bpf_ecdsa_keysize() - Get the key size for ECDSA context
 * @ctx: ECDSA context
 *
 * Returns: Key size in bits, or negative error code on failure
 */
__bpf_kfunc int bpf_ecdsa_keysize(struct bpf_ecdsa_ctx *ctx)
{
	if (!ctx)
		return -EINVAL;

	return crypto_sig_keysize(ctx->tfm);
}

/**
 * bpf_ecdsa_digestsize() - Get the maximum digest size for ECDSA context
 * @ctx: ECDSA context
 */
__bpf_kfunc int bpf_ecdsa_digestsize(struct bpf_ecdsa_ctx *ctx)
{
	if (!ctx)
		return -EINVAL;

	return crypto_sig_digestsize(ctx->tfm);
}

/**
 * bpf_ecdsa_maxsize() - Get the maximum signature size for ECDSA context
 * @ctx: ECDSA context
 */
__bpf_kfunc int bpf_ecdsa_maxsize(struct bpf_ecdsa_ctx *ctx)
{
	if (!ctx)
		return -EINVAL;

	return crypto_sig_maxsize(ctx->tfm);
}
#endif /* CONFIG_CRYPTO_ECDSA */

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(crypt_init_kfunc_btf_ids)
BTF_ID_FLAGS(func, bpf_crypto_ctx_create, KF_ACQUIRE | KF_RET_NULL | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_crypto_ctx_release, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_crypto_ctx_acquire, KF_ACQUIRE | KF_RCU | KF_RET_NULL)
#if IS_ENABLED(CONFIG_CRYPTO_ECDSA)
BTF_ID_FLAGS(func, bpf_ecdsa_ctx_create, KF_ACQUIRE | KF_RET_NULL | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ecdsa_ctx_create_with_privkey, KF_ACQUIRE | KF_RET_NULL | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ecdsa_ctx_release, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_ecdsa_ctx_acquire, KF_ACQUIRE | KF_RCU | KF_RET_NULL)
#endif
BTF_KFUNCS_END(crypt_init_kfunc_btf_ids)

static const struct btf_kfunc_id_set crypt_init_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &crypt_init_kfunc_btf_ids,
};

BTF_KFUNCS_START(crypt_kfunc_btf_ids)
BTF_ID_FLAGS(func, bpf_crypto_decrypt, KF_RCU)
BTF_ID_FLAGS(func, bpf_crypto_encrypt, KF_RCU)
#if IS_ENABLED(CONFIG_CRYPTO_LIB_SHA256)
BTF_ID_FLAGS(func, bpf_sha256_hash, 0)
BTF_ID_FLAGS(func, bpf_sha384_hash, 0)
BTF_ID_FLAGS(func, bpf_sha512_hash, 0)
#endif
#if IS_ENABLED(CONFIG_CRYPTO_ECDSA)
BTF_ID_FLAGS(func, bpf_ecdsa_verify, 0)
BTF_ID_FLAGS(func, bpf_ecdsa_sign, 0)
BTF_ID_FLAGS(func, bpf_ecdsa_keysize, 0)
BTF_ID_FLAGS(func, bpf_ecdsa_digestsize, 0)
BTF_ID_FLAGS(func, bpf_ecdsa_maxsize, 0)
#endif
BTF_KFUNCS_END(crypt_kfunc_btf_ids)

static const struct btf_kfunc_id_set crypt_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &crypt_kfunc_btf_ids,
};

BTF_ID_LIST(bpf_crypto_dtor_ids)
BTF_ID(struct, bpf_crypto_ctx)
BTF_ID(func, bpf_crypto_ctx_release)
#if IS_ENABLED(CONFIG_CRYPTO_ECDSA)
BTF_ID(struct, bpf_ecdsa_ctx)
BTF_ID(func, bpf_ecdsa_ctx_release)
#endif

static int __init crypto_kfunc_init(void)
{
	int ret;
	const struct btf_id_dtor_kfunc bpf_crypto_dtors[] = {
		{
			.btf_id	      = bpf_crypto_dtor_ids[0],
			.kfunc_btf_id = bpf_crypto_dtor_ids[1]
		},
#if IS_ENABLED(CONFIG_CRYPTO_ECDSA)
		{
			.btf_id       = bpf_crypto_dtor_ids[2],
			.kfunc_btf_id = bpf_crypto_dtor_ids[3]
		},
#endif
	};

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &crypt_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_ACT, &crypt_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &crypt_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &crypt_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					       &crypt_init_kfunc_set);
	/* Enable kptr pattern for TC and XDP programs */
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS,
					       &crypt_init_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
					       &crypt_init_kfunc_set);
	return  ret ?: register_btf_id_dtor_kfuncs(bpf_crypto_dtors,
						   ARRAY_SIZE(bpf_crypto_dtors),
						   THIS_MODULE);
}

late_initcall(crypto_kfunc_init);
