// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the UMD asymmetric key parser.
 */

#include <linux/module.h>
#include <crypto/public_key.h>

#include "umd_key.h"

const char *pub_key_algos[PUBKEY_ALGO__LAST] = {
	[PUBKEY_ALGO_RSA] = "rsa",
	[PUBKEY_ALGO_ECDSA] = "ecdsa",
	[PUBKEY_ALGO_ECDSA_NIST_P192] = "ecdsa-nist-p192",
	[PUBKEY_ALGO_ECDSA_NIST_P256] = "ecdsa-nist-p256",
	[PUBKEY_ALGO_ECDSA_NIST_P384] = "ecdsa-nist-p384",
};

struct umd_mgmt key_ops = {
	.info.driver_name = "umd_key_sig_umh",
	.kmod = "umd_key_sig_user",
	.lock = __MUTEX_INITIALIZER(key_ops.lock),
};
EXPORT_SYMBOL_GPL(key_ops);

static struct public_key *get_public_key(struct msg_out *out)
{
	struct public_key *pub;

	if (out->key.pkey_algo >= PUBKEY_ALGO__LAST) {
		pr_err("Unexpected key algo %d\n", out->key.pkey_algo);
		return ERR_PTR(-EBADMSG);
	}

	if (!out->key.pub_key_len) {
		pr_err("Unexpected zero-length for public key\n");
		return ERR_PTR(-EBADMSG);
	}

	if (out->key.pub_key_len > sizeof(out->key.pub_key)) {
		pr_err("Public key length %ld greater than expected %ld\n",
		       out->key.pub_key_len, sizeof(out->key.pub_key));
		return ERR_PTR(-EBADMSG);
	}

	pub = kzalloc(sizeof(*pub), GFP_KERNEL);
	if (!pub)
		return ERR_PTR(-ENOMEM);

	pub->id_type = "UMD";
	pub->pkey_algo = pub_key_algos[out->key.pkey_algo];

	pub->key = kmemdup(out->key.pub_key, out->key.pub_key_len, GFP_KERNEL);
	if (!pub->key) {
		kfree(pub);
		return ERR_PTR(-ENOMEM);
	}

	pub->keylen = out->key.pub_key_len;
	return pub;
}

int umd_get_kids(struct umd_asymmetric_key_ids *umd_kids,
		 struct asymmetric_key_id **id)
{
	int ret = 0, i, j;

	for (i = 0; i < ARRAY_SIZE(umd_kids->kid1_len); i++) {
		if (!umd_kids->kid1_len[i] && !umd_kids->kid2_len[i])
			continue;

		if (umd_kids->kid1_len[i] > sizeof(umd_kids->kid1[0])) {
			pr_err("Key ID 1 length %ld greater than expected %ld\n",
			       umd_kids->kid1_len[i],
			       sizeof(umd_kids->kid1[0]));
			ret = -EBADMSG;
			break;
		}

		if (umd_kids->kid2_len[i] > sizeof(umd_kids->kid2[0])) {
			pr_err("Key ID 2 length %ld greater than expected %ld\n",
			       umd_kids->kid2_len[i],
			       sizeof(umd_kids->kid2[0]));
			ret = -EBADMSG;
			break;
		}

		id[i] = asymmetric_key_generate_id(umd_kids->kid1[i],
						   umd_kids->kid1_len[i],
						   umd_kids->kid2[i],
						   umd_kids->kid2_len[i]);
		if (!id[i]) {
			ret = -ENOMEM;
			break;
		}
	}

	if (ret) {
		for (j = 0; j < i; j++)
			kfree(id[j]);
	}

	return ret;
}

static int umd_key_parse(struct key_preparsed_payload *prep)
{
	struct msg_in *in = NULL;
	struct msg_out *out = NULL;
	struct asymmetric_key_ids *kids = NULL;
	struct public_key *pub = NULL;
	int ret = -ENOMEM;

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		goto out;

	out = kzalloc(sizeof(*out), GFP_KERNEL);
	if (!out)
		goto out;

	in->cmd = CMD_KEY;
	in->data_len = prep->datalen;
	/* Truncate the input, there might be multiple keys in the same blob. */
	memcpy(in->data, prep->data, min(prep->datalen, sizeof(in->data)));

	out->ret = -EINVAL;

	ret = umd_mgmt_send_recv(&key_ops, in, sizeof(*in), out, sizeof(*out));
	if (ret)
		goto out;

	if (out->ret) {
		ret = out->ret;
		goto out;
	}

	pub = get_public_key(out);
	if (IS_ERR(pub)) {
		ret = PTR_ERR(pub);
		pub = NULL;
		goto out;
	}

	kids = kzalloc(sizeof(*kids), GFP_KERNEL);
	if (!kids) {
		ret = -ENOMEM;
		goto out;
	}

	ret = umd_get_kids(&out->key.kids,
			   (struct asymmetric_key_id **)kids->id);
	if (ret)
		goto out;

	if (strlen(out->key.key_desc)) {
		prep->description = kstrdup(out->key.key_desc, GFP_KERNEL);
		if (!prep->description)
			ret = -ENOMEM;
	}

out:
	kfree(in);
	kfree(out);

	if (ret) {
		public_key_free(pub);
		asymmetric_key_free_kids(kids);
		return ret;
	}

	/* We're pinning the module by being linked against it */
	__module_get(public_key_subtype.owner);
	prep->payload.data[asym_subtype] = &public_key_subtype;
	prep->payload.data[asym_key_ids] = kids;
	prep->payload.data[asym_crypto] = pub;
	prep->quotalen = 100;
	return 0;
}

static struct asymmetric_key_parser umd_key_parser = {
	.owner = THIS_MODULE,
	.name = "umd_key",
	.parse = umd_key_parse
};

static int __init umd_key_init(void)
{
	return register_asymmetric_key_parser(&umd_key_parser);
}

static void __exit umd_key_exit(void)
{
	unregister_asymmetric_key_parser(&umd_key_parser);
}

module_init(umd_key_init);
module_exit(umd_key_exit);
MODULE_LICENSE("GPL");
