/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#ifndef _NBL_COMMON_H_
#define _NBL_COMMON_H_

#include <linux/types.h>

#include "../nbl_include/nbl_include.h"
#include "../nbl_include/nbl_def_common.h"

struct nbl_hash_tbl_mgt {
	struct nbl_hash_tbl_key tbl_key;
	struct hlist_head *hash;
	/**
	 * bucket_locks: per-bucket spinlock array
	 * Each hash bucket corresponds to an independent spinlock.
	 * Protects concurrent hash list modification
	 */
	spinlock_t *bucket_locks;
	u16 node_num;
};

struct nbl_hash_entry_node {
	struct hlist_node node;
	void *key;
	void *data;
};

#endif
