// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#include <linux/bitmap.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/err.h>
#include <linux/jhash.h>
#include <linux/random.h>

#define BITSET_MAP_CREATE_FLAG_MASK \
	(BPF_F_NUMA_NODE | BPF_F_ZERO_SEED | BPF_F_ACCESS_MASK)

struct bpf_bitset_map {
	struct bpf_map map;

	/* If the number of hash functions at map creation time is greater
	 * than 0, the bitset map will function as a bloom filter and the fields
	 * in the struct below will be initialized accordingly.
	 */
	struct {
		u32 nr_hash_funcs;
		u32 bitset_mask;
		u32 hash_seed;
		/* If the size of the values in the bloom filter is u32 aligned,
		 * then it is more performant to use jhash2 as the underlying hash
		 * function, else we use jhash. This tracks the number of u32s
		 * in an u32-aligned value size. If the value size is not u32 aligned,
		 * this will be 0.
		 */
		u32 aligned_u32_count;
	} bloom_filter;

	unsigned long bitset[];
};

static inline bool use_bloom_filter(struct bpf_bitset_map *map)
{
	return map->bloom_filter.nr_hash_funcs > 0;
}

static u32 hash(struct bpf_bitset_map *map, void *value,
		u64 value_size, u32 index)
{
	u32 h;

	if (map->bloom_filter.aligned_u32_count)
		h = jhash2(value, map->bloom_filter.aligned_u32_count,
			   map->bloom_filter.hash_seed + index);
	else
		h = jhash(value, value_size, map->bloom_filter.hash_seed + index);

	return h & map->bloom_filter.bitset_mask;
}

static int bitset_map_push_elem(struct bpf_map *map, void *value,
				u64 flags)
{
	struct bpf_bitset_map *bitset_map =
		container_of(map, struct bpf_bitset_map, map);
	u32 i, h, bitset_index;

	if (flags != BPF_ANY)
		return -EINVAL;

	if (use_bloom_filter(bitset_map)) {
		for (i = 0; i < bitset_map->bloom_filter.nr_hash_funcs; i++) {
			h = hash(bitset_map, value, map->value_size, i);
			set_bit(h, bitset_map->bitset);
		}
	} else {
		bitset_index = *(u32 *)value;

		if (bitset_index >= map->max_entries)
			return -EINVAL;

		set_bit(bitset_index, bitset_map->bitset);
	}

	return 0;
}

static int bitset_map_peek_elem(struct bpf_map *map, void *value)
{
	struct bpf_bitset_map *bitset_map =
		container_of(map, struct bpf_bitset_map, map);
	u32 i, h, bitset_index;

	if (use_bloom_filter(bitset_map)) {
		for (i = 0; i < bitset_map->bloom_filter.nr_hash_funcs; i++) {
			h = hash(bitset_map, value, map->value_size, i);
			if (!test_bit(h, bitset_map->bitset))
				return -ENOENT;
		}
	} else {
		bitset_index = *(u32 *)value;
		if (bitset_index  >= map->max_entries)
			return -EINVAL;

		if (!test_bit(bitset_index, bitset_map->bitset))
			return -ENOENT;
	}

	return 0;
}

static int bitset_map_pop_elem(struct bpf_map *map, void *value)
{
	struct bpf_bitset_map *bitset_map =
		container_of(map, struct bpf_bitset_map, map);
	u32 bitset_index;

	if (use_bloom_filter(bitset_map))
		return -EOPNOTSUPP;

	bitset_index = *(u32 *)value;

	if (!test_and_clear_bit(bitset_index, bitset_map->bitset))
		return -EINVAL;

	return 0;
}

static void init_bloom_filter(struct bpf_bitset_map *bitset_map, union bpf_attr *attr,
			      u32 nr_hash_funcs, u32 bitset_mask)
{
	bitset_map->bloom_filter.nr_hash_funcs = nr_hash_funcs;
	bitset_map->bloom_filter.bitset_mask = bitset_mask;

	/* Check whether the value size is u32-aligned */
	if ((attr->value_size & (sizeof(u32) - 1)) == 0)
		bitset_map->bloom_filter.aligned_u32_count =
			attr->value_size / sizeof(u32);

	if (!(attr->map_flags & BPF_F_ZERO_SEED))
		bitset_map->bloom_filter.hash_seed = get_random_int();
}

static struct bpf_map *bitset_map_alloc(union bpf_attr *attr)
{
	int numa_node = bpf_map_attr_numa_node(attr);
	u32 bitset_bytes, bitset_mask, nr_hash_funcs;
	struct bpf_bitset_map *bitset_map;
	u64 nr_bits_roundup_pow2;

	if (!bpf_capable())
		return ERR_PTR(-EPERM);

	if (attr->key_size != 0 || attr->max_entries == 0 ||
	    attr->map_flags & ~BITSET_MAP_CREATE_FLAG_MASK ||
	    !bpf_map_flags_access_ok(attr->map_flags))
		return ERR_PTR(-EINVAL);

	if (attr->map_extra & ~0xF)
		return ERR_PTR(-EINVAL);

	/* The lower 4 bits of map_extra specify the number of hash functions */
	nr_hash_funcs = attr->map_extra & 0xF;

	if (!nr_hash_funcs) {
		if (attr->value_size != sizeof(u32))
			return ERR_PTR(-EINVAL);

		/* Round up to the size of an unsigned long since a bit gets set
		 * at the granularity of an unsigned long.
		 */
		bitset_bytes = roundup(BITS_TO_BYTES(attr->max_entries),
				       sizeof(unsigned long));
	} else {
		/* If the number of hash functions > 0, then the map will
		 * function as a bloom filter
		 */

		if (attr->value_size == 0)
			return ERR_PTR(-EINVAL);

		/* We round up the size of the bitset to the nearest power of two to
		 * enable more efficient hashing using a bitmask. The bitmask will be
		 * the bitset size - 1.
		 */
		nr_bits_roundup_pow2 = roundup_pow_of_two(attr->max_entries);
		bitset_mask = nr_bits_roundup_pow2 - 1;

		bitset_bytes = roundup(BITS_TO_BYTES(nr_bits_roundup_pow2),
				       sizeof(unsigned long));
	}

	bitset_map = bpf_map_area_alloc(sizeof(*bitset_map) + bitset_bytes,
					numa_node);
	if (!bitset_map)
		return ERR_PTR(-ENOMEM);

	bpf_map_init_from_attr(&bitset_map->map, attr);

	if (nr_hash_funcs)
		init_bloom_filter(bitset_map, attr, nr_hash_funcs, bitset_mask);

	return &bitset_map->map;
}

static void bitset_map_free(struct bpf_map *map)
{
	struct bpf_bitset_map *bitset_map =
		container_of(map, struct bpf_bitset_map, map);

	bpf_map_area_free(bitset_map);
}

static void *bitset_map_lookup_elem(struct bpf_map *map, void *key)
{
	/* The eBPF program should use map_peek_elem instead */
	return ERR_PTR(-EINVAL);
}

static int bitset_map_update_elem(struct bpf_map *map, void *key,
				  void *value, u64 flags)
{
	/* The eBPF program should use map_push_elem instead */
	return -EINVAL;
}

static int bitset_map_delete_elem(struct bpf_map *map, void *key)
{
	return -EOPNOTSUPP;
}

static int bitset_map_get_next_key(struct bpf_map *map, void *key,
				   void *next_key)
{
	return -EOPNOTSUPP;
}

static int bitset_map_check_btf(const struct bpf_map *map, const struct btf *btf,
				const struct btf_type *key_type,
				const struct btf_type *value_type)
{
	/* Bitset maps are keyless */
	return btf_type_is_void(key_type) ? 0 : -EINVAL;
}

static int bpf_bitset_map_btf_id;
const struct bpf_map_ops bitset_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc = bitset_map_alloc,
	.map_free = bitset_map_free,
	.map_push_elem = bitset_map_push_elem,
	.map_peek_elem = bitset_map_peek_elem,
	.map_pop_elem = bitset_map_pop_elem,
	.map_lookup_elem = bitset_map_lookup_elem,
	.map_update_elem = bitset_map_update_elem,
	.map_delete_elem = bitset_map_delete_elem,
	.map_get_next_key = bitset_map_get_next_key,
	.map_check_btf = bitset_map_check_btf,
	.map_btf_name = "bpf_bitset_map",
	.map_btf_id = &bpf_bitset_map_btf_id,
};
