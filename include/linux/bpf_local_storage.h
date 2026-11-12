/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2019 Facebook
 * Copyright 2020 Google LLC.
 */

#ifndef _BPF_LOCAL_STORAGE_H
#define _BPF_LOCAL_STORAGE_H

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/rculist.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/types.h>
#include <linux/bpf_mem_alloc.h>
#include <uapi/linux/btf.h>
#include <asm/rqspinlock.h>

#define BPF_LOCAL_STORAGE_CACHE_SIZE	16

struct bpf_local_storage_map_bucket {
	struct hlist_head list;
	rqspinlock_t lock;
};

/* Thp map is not the primary owner of a bpf_local_storage_elem.
 * Instead, the container object (eg. sk->sk_bpf_storage) is.
 *
 * The map (bpf_local_storage_map) is for two purposes
 * 1. Define the size of the "local storage".  It is
 *    the map's value_size.
 *
 * 2. Maintain a list to keep track of all elems such
 *    that they can be cleaned up during the map destruction.
 *
 * When a bpf local storage is being looked up for a
 * particular object,  the "bpf_map" pointer is actually used
 * as the "key" to search in the list of elem in
 * the respective bpf_local_storage owned by the object.
 *
 * e.g. sk->sk_bpf_storage is the mini-map with the "bpf_map" pointer
 * as the searching key.
 */
struct bpf_local_storage_map {
	struct bpf_map map;
	/* Lookup elem does not require accessing the map.
	 *
	 * Updating/Deleting requires a bucket lock to
	 * link/unlink the elem from the map.  Having
	 * multiple buckets to improve contention.
	 */
	struct bpf_local_storage_map_bucket *buckets;
	struct bpf_local_storage_cache *cache;
	u32 bucket_log;
	u16 elem_size;
	u16 cache_idx;
	/*
	 * Byte offset of the inline slot of a BPF_F_INLINE_VALUE map from the
	 * start of the storage object, and the end of the slot. 0: no slot.
	 */
	u16 inline_off;
	u16 inline_end;
	u32 inline_claim;	/* Claim number of the slot, the source of its tag */
};

struct bpf_local_storage_data {
	/* smap is used as the searching key when looking up
	 * from the object's bpf_local_storage.
	 *
	 * Put it in the same cacheline as the data to minimize
	 * the number of cachelines accessed during the cache hit case.
	 *
	 * An inline slot has the same layout, with a tag in place of smap:
	 * the tag of the map whose value is in the slot. Any other tag (0
	 * after a delete) means no value. A slot is not in an selem: never
	 * apply SELEM() to it.
	 */
	union {
		struct bpf_local_storage_map __rcu *smap;
		u64 inline_tag;
	};
	u8 data[] __aligned(8);
};

#define SELEM_MAP_UNLINKED	(1 << 0)
#define SELEM_STORAGE_UNLINKED	(1 << 1)
#define SELEM_UNLINKED		(SELEM_MAP_UNLINKED | SELEM_STORAGE_UNLINKED)
#define SELEM_TOFREE		(1 << 2)

/* Linked to bpf_local_storage and bpf_local_storage_map */
struct bpf_local_storage_elem {
	struct hlist_node map_node;	/* Linked to bpf_local_storage_map */
	struct hlist_node snode;	/* Linked to bpf_local_storage */
	struct bpf_local_storage __rcu *local_storage;
	union {
		struct rcu_head rcu;
		struct hlist_node free_node;	/* used to postpone
						 * bpf_selem_free
						 * after raw_spin_unlock
						 */
	};
	atomic_t state;
	/* 4 bytes hole */
	/* The data is stored in another cacheline to minimize
	 * the number of cachelines access during a cache hit.
	 */
	struct bpf_local_storage_data sdata ____cacheline_aligned;
};

struct bpf_local_storage {
	struct bpf_local_storage_data __rcu *cache[BPF_LOCAL_STORAGE_CACHE_SIZE];
	struct hlist_head list; /* List of bpf_local_storage_elem */
	void *owner;		/* The object that owns the above "list" of
				 * bpf_local_storage_elem.
				 */
	struct rcu_head rcu;
	rqspinlock_t lock;	/* Protect adding/removing from the "list" */
	u32 obj_size;		/* Size of this object. It does not change. */
	u64 mem_charge;		/* Copy of mem charged to owner. Protected by "lock" */
	refcount_t owner_refcnt;/* Used to pin owner when map_free is uncharging */
	bool dying;		/* destroy() has run. Only with an inline area */
};

/*
 * A program can hold a pointer into the inline area without an selem. So an
 * object with an inline area lives until its owner goes away.
 */
static inline bool
bpf_local_storage_has_inline(const struct bpf_local_storage *local_storage)
{
	return local_storage->obj_size > sizeof(*local_storage);
}

/*
 * Drop a reference got by refcount_inc_not_zero(&local_storage->owner_refcnt).
 * bpf_local_storage_destroy() may have dropped the owner's reference meanwhile
 * and wait for the count to reach zero, so this one can be the last.
 */
static inline void
bpf_local_storage_unpin_owner(struct bpf_local_storage *local_storage)
{
	bool last __maybe_unused;

	last = refcount_dec_and_test(&local_storage->owner_refcnt);
}

/* U16_MAX is much more than enough for sk local storage
 * considering a tcp_sock is ~2k.
 */
#define BPF_LOCAL_STORAGE_MAX_VALUE_SIZE				       \
	min_t(u32,                                                             \
	      (KMALLOC_MAX_SIZE - MAX_BPF_STACK -                              \
	       sizeof(struct bpf_local_storage_elem)),                         \
	      (U16_MAX - sizeof(struct bpf_local_storage_elem)))

#define SELEM(_SDATA)                                                          \
	container_of((_SDATA), struct bpf_local_storage_elem, sdata)
#define SDATA(_SELEM) (&(_SELEM)->sdata)

#define BPF_LOCAL_STORAGE_CACHE_SIZE	16

/*
 * The inline area of a storage object goes from the end of the struct to
 * at most 1 KB. A slot is an 8 byte tag, then the value.
 */
#define BPF_LOCAL_STORAGE_INLINE_MAX	1024
#define BPF_LOCAL_STORAGE_INLINE_START	ALIGN(sizeof(struct bpf_local_storage), 8)
/*
 * Inline maps per owner type. The same as the cache size on purpose: more
 * maps than that share cache[] entries, so they gain less from a slot.
 */
#define BPF_LOCAL_STORAGE_INLINE_MAPS	16

/* A later patch adds this flag to the UAPI and allows it */
#define BPF_F_INLINE_VALUE		BIT(20)

struct bpf_local_storage_cache {
	spinlock_t idx_lock;
	u64 idx_usage_counts[BPF_LOCAL_STORAGE_CACHE_SIZE];
	/*
	 * The live inline maps, NULL if free. Few entries keep the scans in
	 * map create and sk diag cheap. Written under idx_lock.
	 */
	struct bpf_local_storage_map __rcu *inline_maps[BPF_LOCAL_STORAGE_INLINE_MAPS];
	/* Largest slot end in inline_maps[], so new objects read no map */
	u32 inline_end;
	u32 inline_claims;	/* Number of claims, the source of slot tags */
};

#define DEFINE_BPF_STORAGE_CACHE(name)				\
static struct bpf_local_storage_cache name = {			\
	.idx_lock = __SPIN_LOCK_UNLOCKED(name.idx_lock),	\
}

/* Helper functions for bpf_local_storage */
int bpf_local_storage_map_alloc_check(union bpf_attr *attr);

struct bpf_map *
bpf_local_storage_map_alloc(union bpf_attr *attr,
			    struct bpf_local_storage_cache *cache);

void __bpf_local_storage_insert_cache(struct bpf_local_storage *local_storage,
				      struct bpf_local_storage_map *smap,
				      struct bpf_local_storage_elem *selem);

/*
 * smap has an inline slot. The tag needs an 8 byte acquire and release, so
 * slots are 64-bit only: on 32-bit, false lets the compiler drop the slot
 * code. There is no hint on the inline_off test, so that inline maps do not
 * pay for normal maps.
 */
static __always_inline bool
bpf_local_storage_map_inline(const struct bpf_local_storage_map *smap)
{
	return IS_ENABLED(CONFIG_64BIT) && smap->inline_off;
}

/* The inline slot of smap, or NULL if local_storage does not hold it */
static __always_inline struct bpf_local_storage_data *
bpf_local_storage_inline(struct bpf_local_storage *local_storage,
			 struct bpf_local_storage_map *smap)
{
	if (!bpf_local_storage_map_inline(smap) ||
	    smap->inline_end > local_storage->obj_size)
		return NULL;
	return (void *)local_storage + smap->inline_off;
}

static inline u64 bpf_local_storage_inline_tag(const struct bpf_local_storage_map *smap)
{
	return (u64)~smap->inline_claim << 32 | smap->inline_claim;
}

/* The slot holds a value of smap */
static __always_inline bool
bpf_local_storage_inline_valid(struct bpf_local_storage_data *sdata,
			       const struct bpf_local_storage_map *smap)
{
	/* Pairs with the tag release in an update: see the value */
	return smp_load_acquire(&sdata->inline_tag) ==
	       bpf_local_storage_inline_tag(smap);
}

/* If cacheit_lockit is false, this lookup function is lockless */
static inline struct bpf_local_storage_data *
bpf_local_storage_lookup(struct bpf_local_storage *local_storage,
			 struct bpf_local_storage_map *smap,
			 bool cacheit_lockit)
{
	struct bpf_local_storage_data *sdata;
	struct bpf_local_storage_elem *selem;

	/*
	 * An object that holds the slot of smap never has an selem of smap:
	 * the object size does not change, and a create puts the value in
	 * the slot.
	 */
	sdata = bpf_local_storage_inline(local_storage, smap);
	if (sdata)
		return bpf_local_storage_inline_valid(sdata, smap) ? sdata : NULL;

	/* Fast path (cache hit) */
	sdata = rcu_dereference_check(local_storage->cache[smap->cache_idx],
				      bpf_rcu_lock_held());
	if (sdata && rcu_access_pointer(sdata->smap) == smap)
		return sdata;

	/* Slow path (cache miss) */
	hlist_for_each_entry_rcu(selem, &local_storage->list, snode,
				  rcu_read_lock_trace_held())
		if (rcu_access_pointer(SDATA(selem)->smap) == smap)
			break;

	if (!selem)
		return NULL;
	if (cacheit_lockit)
		__bpf_local_storage_insert_cache(local_storage, smap, selem);
	return SDATA(selem);
}

u32 bpf_local_storage_destroy(struct bpf_local_storage *local_storage);

void bpf_local_storage_map_free(struct bpf_map *map,
				struct bpf_local_storage_cache *cache);

int bpf_local_storage_map_check_btf(struct bpf_map *map,
				    const struct btf *btf,
				    const struct btf_type *key_type,
				    const struct btf_type *value_type);

void bpf_selem_link_storage_nolock(struct bpf_local_storage *local_storage,
				   struct bpf_local_storage_elem *selem);

int bpf_selem_unlink(struct bpf_local_storage_elem *selem);

int bpf_local_storage_delete(void *owner, struct bpf_local_storage_map *smap);

int bpf_selem_link_map(struct bpf_local_storage_map *smap,
		       struct bpf_local_storage *local_storage,
		       struct bpf_local_storage_elem *selem);

struct bpf_local_storage_elem *
bpf_selem_alloc(struct bpf_local_storage_map *smap, void *owner, void *value,
		bool swap_uptrs);

void bpf_selem_free(struct bpf_local_storage_elem *selem,
		    bool reuse_now);

struct bpf_local_storage *
bpf_local_storage_alloc(void *owner,
			struct bpf_local_storage_map *smap,
			struct bpf_local_storage_elem *first_selem,
			void *value);

struct bpf_local_storage_data *
bpf_local_storage_update(void *owner, struct bpf_local_storage_map *smap,
			 void *value, u64 map_flags, bool swap_uptrs);

u64 bpf_local_storage_map_mem_usage(const struct bpf_map *map);

#endif /* _BPF_LOCAL_STORAGE_H */
