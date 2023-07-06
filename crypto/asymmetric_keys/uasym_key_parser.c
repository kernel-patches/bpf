// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the user asymmetric key parser.
 */

#define pr_fmt(fmt) "UASYM KEY: "fmt
#include <linux/module.h>
#include <crypto/public_key.h>
#include <crypto/pub_key_info.h>

#include "uasym_parser.h"

static int parse_key_pub(struct public_key *pub, enum fields field,
			 const u8 *field_data, u32 field_data_len)
{
	int ret = 0;

	kenter(",%u,%u", field, field_data_len);

	pub->key = kmemdup(field_data, field_data_len, GFP_KERNEL);
	if (!pub->key) {
		ret = -ENOMEM;
		goto out;
	}

	pub->keylen = field_data_len;
	pr_debug("Key length in bytes: %d\n", pub->keylen);
out:
	kleave(" = %d", ret);
	return ret;
}

int parse_key_algo(const char **pkey_algo, enum fields field,
		   const u8 *field_data, u32 field_data_len)
{
	u8 algo;
	int ret = 0;

	kenter(",%u,%u", field, field_data_len);

	if (field_data_len != sizeof(u8)) {
		pr_debug("Unexpected data length %u, expected %lu\n",
			 field_data_len, sizeof(u8));
		ret = -EBADMSG;
		goto out;
	}

	algo = *field_data;

	if (algo >= PKEY_ALGO__LAST) {
		pr_debug("Unexpected public key algo %u\n", algo);
		ret = -EBADMSG;
		goto out;
	}

	*pkey_algo = pub_key_algo_name[algo];
	pr_debug("Public key algo: %s\n", *pkey_algo);
out:
	kleave(" = %d", ret);
	return ret;
}

int parse_key_kid(struct asymmetric_key_id **id, enum fields field,
		  const u8 *field_data, u32 field_data_len)
{
	int ret = 0;

	kenter(",%u,%u", field, field_data_len);

	*id = asymmetric_key_generate_id(field_data, field_data_len, NULL, 0);
	if (!*id) {
		ret = -ENOMEM;
		goto out;
	}

	pr_debug("Key/auth identifier: %*phN\n", (*id)->len, (*id)->data);
out:
	kleave(" = %d", ret);
	return ret;
}

static int parse_key_desc(struct key_preparsed_payload *prep, enum fields field,
			  const u8 *field_data, u32 field_data_len)
{
	int ret = 0;

	kenter(",%u,%u", field, field_data_len);

	if (field_data[field_data_len - 1] != '\0') {
		pr_err("Non-terminated string\n");
		ret = -EBADMSG;
		goto out;
	}

	prep->description = kstrndup(field_data, field_data_len, GFP_KERNEL);
	if (!prep->description) {
		ret = -ENOMEM;
		goto out;
	}

	pr_debug("Key description: %s\n", prep->description);
out:
	kleave(" = %d", ret);
	return ret;
}

struct callback_struct {
	struct public_key *pub;
	struct asymmetric_key_ids *kids;
	struct key_preparsed_payload *prep;
};

static int key_callback(void *callback_data, enum fields field,
			const u8 *field_data, u32 field_data_len)
{
	struct callback_struct *cb_s = (struct callback_struct *)callback_data;
	struct asymmetric_key_id **id;
	int ret;

	switch (field) {
	case KEY_PUB:
		ret = parse_key_pub(cb_s->pub, field, field_data,
				    field_data_len);
		break;
	case KEY_ALGO:
		ret = parse_key_algo(&cb_s->pub->pkey_algo, field, field_data,
				     field_data_len);
		break;
	case KEY_KID0:
		id = (struct asymmetric_key_id **)&cb_s->kids->id[0];
		ret = parse_key_kid(id, field, field_data, field_data_len);
		break;
	case KEY_KID1:
		id = (struct asymmetric_key_id **)&cb_s->kids->id[1];
		ret = parse_key_kid(id, field, field_data, field_data_len);
		break;
	case KEY_KID2:
		id = (struct asymmetric_key_id **)&cb_s->kids->id[2];
		ret = parse_key_kid(id, field, field_data, field_data_len);
		break;
	case KEY_DESC:
		ret = parse_key_desc(cb_s->prep, field, field_data,
				     field_data_len);
		break;
	default:
		/* Just ignore non-relevant fields. */
		ret = 0;
		break;
	}

	return ret;
}

static int uasym_key_parse(struct key_preparsed_payload *prep)
{
	struct callback_struct cb_s;
	int ret;

	kenter("");

	cb_s.pub = kzalloc(sizeof(*cb_s.pub), GFP_KERNEL);
	if (!cb_s.pub) {
		ret = -ENOMEM;
		goto out;
	}

	cb_s.pub->id_type = "UASYM_KEY";

	cb_s.kids = kzalloc(sizeof(*cb_s.kids), GFP_KERNEL);
	if (!cb_s.kids) {
		ret = -ENOMEM;
		goto out;
	}

	cb_s.prep = prep;

	ret = uasym_parse(TYPE_KEY, key_callback, &cb_s, prep->data,
			  prep->datalen);
	if (ret < 0)
		goto out;

	if (!cb_s.pub->key || !cb_s.pub->pkey_algo ||
	    (!cb_s.kids->id[0] && !cb_s.kids->id[1] && !cb_s.kids->id[2])) {
		pr_debug("Incomplete data\n");
		ret = -ENOENT;
		goto out;
	}

	/* We're pinning the module by being linked against it */
	__module_get(public_key_subtype.owner);
	prep->payload.data[asym_subtype] = &public_key_subtype;
	prep->payload.data[asym_key_ids] = cb_s.kids;
	prep->payload.data[asym_crypto] = cb_s.pub;
	prep->quotalen = 100;
out:
	kleave(" = %d", ret);

	if (ret < 0) {
		public_key_free(cb_s.pub);
		asymmetric_key_free_kids(cb_s.kids);
		return ret;
	}

	return 0;
}

static struct asymmetric_key_parser uasym_key_parser = {
	.owner = THIS_MODULE,
	.name = "uasym_key",
	.parse = uasym_key_parse
};

static int __init uasym_key_init(void)
{
	return register_asymmetric_key_parser(&uasym_key_parser);
}

static void __exit uasym_key_exit(void)
{
	unregister_asymmetric_key_parser(&uasym_key_parser);
}

module_init(uasym_key_init);
module_exit(uasym_key_exit);
MODULE_LICENSE("GPL");
