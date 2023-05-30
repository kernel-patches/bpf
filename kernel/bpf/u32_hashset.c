// SPDX-License-Identifier: GPL-2.0-only

#include "linux/gfp_types.h"
#include "linux/random.h"
#include "linux/slab.h"
#include <linux/jhash.h>

#include "u32_hashset.h"

static struct u32_hashset_bucket *u32_hashset_put_in_bucket(struct u32_hashset_bucket *bucket,
							    u32 item)
{
	struct u32_hashset_bucket *new_bucket;
	u32 new_cap = bucket ? 2 * bucket->cap : 1;
	u32 cnt = bucket ? bucket->cnt : 0;
	size_t sz;

	if (!bucket || bucket->cnt == bucket->cap) {
		sz = sizeof(struct u32_hashset_bucket) + sizeof(u32) * new_cap;
		new_bucket = krealloc(bucket, sz, GFP_KERNEL);
		if (!new_bucket)
			return NULL;
		new_bucket->cap = new_cap;
	} else {
		new_bucket = bucket;
	}

	new_bucket->items[cnt] = item;
	new_bucket->cnt = cnt + 1;

	return new_bucket;
}

static bool u32_hashset_needs_to_grow(struct u32_hashset *set)
{
	/* grow if empty or more than 75% filled */
	return (set->buckets_cnt == 0) || ((set->items_cnt + 1) * 4 / 3 > set->buckets_cnt);
}

static void u32_hashset_free_buckets(struct u32_hashset_bucket **buckets, size_t cnt)
{
	size_t bkt;

	for (bkt = 0; bkt < cnt; ++bkt)
		kfree(buckets[bkt]);
	kfree(buckets);
}

static int u32_hashset_grow(struct u32_hashset *set)
{
	struct u32_hashset_bucket **new_buckets;
	size_t new_buckets_cnt;
	size_t h, bkt, i;
	u32 item;

	new_buckets_cnt = set->buckets_cnt ? set->buckets_cnt * 2 : 4;
	new_buckets = kcalloc(new_buckets_cnt, sizeof(new_buckets[0]), GFP_KERNEL);
	if (!new_buckets)
		return -ENOMEM;

	for (bkt = 0; bkt < set->buckets_cnt; ++bkt) {
		if (!set->buckets[bkt])
			continue;

		for (i = 0; i < set->buckets[bkt]->cnt; ++i) {
			item = set->buckets[bkt]->items[i];
			h = jhash_1word(item, set->seed) % new_buckets_cnt;
			new_buckets[h] = u32_hashset_put_in_bucket(new_buckets[h], item);
			if (!new_buckets[h])
				goto nomem;
		}
	}

	u32_hashset_free_buckets(set->buckets, set->buckets_cnt);
	set->buckets_cnt = new_buckets_cnt;
	set->buckets = new_buckets;
	return 0;

nomem:
	u32_hashset_free_buckets(new_buckets, new_buckets_cnt);

	return -ENOMEM;
}

void u32_hashset_clear(struct u32_hashset *set)
{
	u32_hashset_free_buckets(set->buckets, set->buckets_cnt);
	set->buckets = NULL;
	set->buckets_cnt = 0;
	set->items_cnt = 0;
}

bool u32_hashset_find(const struct u32_hashset *set, const u32 key)
{
	struct u32_hashset_bucket *bkt;
	u32 i, hash;

	if (!set->buckets)
		return false;

	hash = jhash_1word(key, set->seed) % set->buckets_cnt;
	bkt = set->buckets[hash];
	if (!bkt)
		return false;

	for (i = 0; i < bkt->cnt; ++i)
		if (bkt->items[i] == key)
			return true;

	return false;
}

int u32_hashset_add(struct u32_hashset *set, u32 key)
{
	struct u32_hashset_bucket *new_bucket;
	u32 hash;
	int err;

	if (u32_hashset_find(set, key))
		return 0;

	if (u32_hashset_needs_to_grow(set)) {
		err = u32_hashset_grow(set);
		if (err)
			return err;
	}

	hash = jhash_1word(key, set->seed) % set->buckets_cnt;
	new_bucket = u32_hashset_put_in_bucket(set->buckets[hash], key);
	if (!new_bucket)
		return -ENOMEM;

	set->buckets[hash] = new_bucket;
	set->items_cnt++;

	return 0;
}
