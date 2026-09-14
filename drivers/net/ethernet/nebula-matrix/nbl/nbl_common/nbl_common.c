// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#include <linux/device.h>
#include <linux/jhash.h>
#include "nbl_common.h"

void nbl_common_destroy_wq(struct nbl_common_info *common)
{
	if (!common || !common->wq)
		return;

	destroy_workqueue(common->wq);
	common->wq = NULL;
}

int nbl_common_create_wq(struct nbl_common_info *common)
{
	char wq_name[32];

	snprintf(wq_name, sizeof(wq_name), "nbl_wq_%s", pci_name(common->pdev));
	common->wq = alloc_workqueue(wq_name, WQ_UNBOUND, 0);
	if (!common->wq) {
		dev_err(common->dev, "Failed to alloc workqueue %s\n", wq_name);
		return -ENOMEM;
	}

	return 0;
}

static u32 nbl_common_calc_hash_key(void *key, u32 key_size, u32 bucket_size)
{
	u32 hash;

	if (bucket_size == 0 || bucket_size == 1)
		return 0;

	hash = jhash(key, key_size, 0);

	/* Use bitmask if bucket_size is a power of 2 */
	if ((bucket_size & (bucket_size - 1)) == 0)
		return hash & (bucket_size - 1);
	return hash % bucket_size;
}

/**
 * nbl_common_init_hash_table - initialize per-device hash table
 * @key: hash table creation parameters
 *
 * Return: allocated tbl mgt pointer, NULL on failure.
 */
struct nbl_hash_tbl_mgt *
nbl_common_init_hash_table(struct nbl_hash_tbl_key *key)
{
	struct nbl_hash_tbl_mgt *tbl_mgt;
	u32 bucket_size;
	u32 i;

	tbl_mgt = devm_kzalloc(key->dev, sizeof(*tbl_mgt), GFP_KERNEL);
	if (!tbl_mgt)
		return NULL;

	bucket_size = key->bucket_size;
	tbl_mgt->hash = devm_kcalloc(key->dev, bucket_size,
				     sizeof(struct hlist_head), GFP_KERNEL);
	if (!tbl_mgt->hash)
		return NULL;

	tbl_mgt->bucket_locks = devm_kcalloc(key->dev, bucket_size,
					     sizeof(spinlock_t), GFP_KERNEL);
	if (!tbl_mgt->bucket_locks)
		return NULL;

	for (i = 0; i < bucket_size; i++) {
		INIT_HLIST_HEAD(&tbl_mgt->hash[i]);
		spin_lock_init(&tbl_mgt->bucket_locks[i]);
	}

	memcpy(&tbl_mgt->tbl_key, key, sizeof(tbl_mgt->tbl_key));
	tbl_mgt->node_num = 0;

	return tbl_mgt;
}

/**
 * nbl_common_alloc_hash_node - insert handler node into hash table
 * @tbl_mgt: hash table manager
 * @key: match key (msg_type)
 * @data: handler callback info
 * @out_data: optional pointer to return allocated data ptr
 *
 * Caller context: process context for dynamic registration, init path safe.
 * Protected by per-bucket spin_lock_bh to avoid race with concurrent lookup.
 *
 * Return: 0 on success, -ENOMEM on allocation failure.
 */
int nbl_common_alloc_hash_node(struct nbl_hash_tbl_mgt *tbl_mgt, void *key,
			       void *data, void **out_data)
{
	struct nbl_hash_entry_node *hash_node;
	u16 data_size;
	u16 node_size;
	u32 hash_val;
	u16 key_size;

	node_size = sizeof(*hash_node);
	hash_node = kzalloc(node_size, GFP_KERNEL);
	if (!hash_node)
		return -ENOMEM;

	key_size = tbl_mgt->tbl_key.key_size;
	hash_node->key = kzalloc(key_size, GFP_KERNEL);
	if (!hash_node->key)
		goto alloc_key_failed;

	data_size = tbl_mgt->tbl_key.data_size;
	hash_node->data = kzalloc(data_size, GFP_KERNEL);
	if (!hash_node->data)
		goto alloc_data_failed;

	memcpy(hash_node->key, key, key_size);
	memcpy(hash_node->data, data, data_size);

	hash_val = nbl_common_calc_hash_key(key, key_size,
					    tbl_mgt->tbl_key.bucket_size);

	spin_lock_bh(&tbl_mgt->bucket_locks[hash_val]);
	hlist_add_head(&hash_node->node, tbl_mgt->hash + hash_val);
	tbl_mgt->node_num++;
	spin_unlock_bh(&tbl_mgt->bucket_locks[hash_val]);

	if (out_data)
		*out_data = hash_node->data;

	return 0;

alloc_data_failed:
	kfree(hash_node->key);
alloc_key_failed:
	kfree(hash_node);
	return -ENOMEM;
}

/**
 * nbl_common_get_hash_node - lookup handler from hash table
 * @tbl_mgt: hash table manager
 * @key: lookup key
 *
 * All accessors use spin_lock_bh so that process-context holders
 * disable softirq and cannot deadlock against a concurrent softirq
 * caller (e.g. NAPI RX path).  Safe in both process and softirq
 * context.
 *
 * Return: attached handler data if found, NULL otherwise.
 */
void *nbl_common_get_hash_node(struct nbl_hash_tbl_mgt *tbl_mgt, void *key)
{
	struct nbl_hash_entry_node *hash_node;
	struct hlist_head *head;
	void *data = NULL;
	u32 hash_val;
	u16 key_size;

	key_size = tbl_mgt->tbl_key.key_size;
	hash_val = nbl_common_calc_hash_key(key, key_size,
					    tbl_mgt->tbl_key.bucket_size);
	head = tbl_mgt->hash + hash_val;

	spin_lock_bh(&tbl_mgt->bucket_locks[hash_val]);
	hlist_for_each_entry(hash_node, head, node) {
		if (!memcmp(hash_node->key, key, key_size)) {
			data = hash_node->data;
			break;
		}
	}
	spin_unlock_bh(&tbl_mgt->bucket_locks[hash_val]);

	return data;
}

/*
 * Free all hash nodes in the table.
 */
void nbl_common_remove_hash_table(struct nbl_hash_tbl_mgt *tbl_mgt)
{
	struct nbl_hash_entry_node *hash_node;
	struct hlist_node *safe_node;
	struct hlist_head *head;
	u32 i;

	if (!tbl_mgt)
		return;

	for (i = 0; i < tbl_mgt->tbl_key.bucket_size; i++) {
		head = tbl_mgt->hash + i;

		spin_lock_bh(&tbl_mgt->bucket_locks[i]);
		hlist_for_each_entry_safe(hash_node, safe_node, head, node) {
			hlist_del(&hash_node->node);
			tbl_mgt->node_num--;
			kfree(hash_node->key);
			kfree(hash_node->data);
			kfree(hash_node);
		}
		spin_unlock_bh(&tbl_mgt->bucket_locks[i]);
	}
}
