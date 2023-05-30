// SPDX-License-Identifier: GPL-2.0-only

/* A hashset for u32 values, based on tools/lib/bpf/hashmap.h */

#ifndef __U32_HASHSET_H__
#define __U32_HASHSET_H__

#include "linux/gfp_types.h"
#include "linux/random.h"
#include "linux/slab.h"
#include <linux/jhash.h>

struct u32_hashset_bucket {
	u32 cnt;
	u32 cap;
	u32 items[];
};

struct u32_hashset {
	struct u32_hashset_bucket **buckets;
	size_t buckets_cnt;
	size_t items_cnt;
	u32 seed;
};

void u32_hashset_clear(struct u32_hashset *set);
bool u32_hashset_find(const struct u32_hashset *set, const u32 key);
int u32_hashset_add(struct u32_hashset *set, u32 key);

#endif /* __U32_HASHSET_H__ */
