// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#include <linux/bitmap.h>
#include <linux/bpf.h>
#include <linux/err.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/spinlock.h>

#define BLOOM_FILTER_CREATE_FLAG_MASK \
	(BPF_F_NUMA_NODE | BPF_F_ZERO_SEED | BPF_F_ACCESS_MASK)

struct bpf_bloom_filter {
	struct bpf_map map;
	u32 bit_array_mask;
	u32 hash_seed;
	/* Used for synchronizing parallel writes to the bit array */
	spinlock_t spinlock;
	unsigned long bit_array[];
};

static int bloom_filter_map_peek_elem(struct bpf_map *map, void *value)
{
	struct bpf_bloom_filter *bloom_filter =
		container_of(map, struct bpf_bloom_filter, map);
	u32 i, hash;

	for (i = 0; i < bloom_filter->map.nr_hashes; i++) {
		hash = jhash(value, map->value_size, bloom_filter->hash_seed + i) &
			bloom_filter->bit_array_mask;
		if (!test_bit(hash, bloom_filter->bit_array))
			return -ENOENT;
	}

	return 0;
}

static struct bpf_map *bloom_filter_map_alloc(union bpf_attr *attr)
{
	int numa_node = bpf_map_attr_numa_node(attr);
	u32 nr_bits, bit_array_bytes, bit_array_mask;
	struct bpf_bloom_filter *bloom_filter;

	if (!bpf_capable())
		return ERR_PTR(-EPERM);

	if (attr->key_size != 0 || attr->value_size == 0 || attr->max_entries == 0 ||
	    attr->nr_hashes == 0 || attr->map_flags & ~BLOOM_FILTER_CREATE_FLAG_MASK ||
	    !bpf_map_flags_access_ok(attr->map_flags))
		return ERR_PTR(-EINVAL);

	/* For the bloom filter, the optimal bit array size that minimizes the
	 * false positive probability is n * k / ln(2) where n is the number of
	 * expected entries in the bloom filter and k is the number of hash
	 * functions. We use 7 / 5 to approximate 1 / ln(2).
	 *
	 * We round this up to the nearest power of two to enable more efficient
	 * hashing using bitmasks. The bitmask will be the bit array size - 1.
	 *
	 * If this overflows a u32, the bit array size will have 2^32 (4
	 * GB) bits.
	 */
	if (unlikely(check_mul_overflow(attr->max_entries, attr->nr_hashes, &nr_bits)) ||
	    unlikely(check_mul_overflow(nr_bits / 5, (u32)7, &nr_bits)) ||
	    unlikely(nr_bits > (1UL << 31))) {
		/* The bit array size is 2^32 bits but to avoid overflowing the
		 * u32, we use BITS_TO_BYTES(U32_MAX), which will round up to the
		 * equivalent number of bytes
		 */
		bit_array_bytes = BITS_TO_BYTES(U32_MAX);
		bit_array_mask = U32_MAX;
	} else {
		if (nr_bits <= BITS_PER_LONG)
			nr_bits = BITS_PER_LONG;
		else
			nr_bits = roundup_pow_of_two(nr_bits);
		bit_array_bytes = BITS_TO_BYTES(nr_bits);
		bit_array_mask = nr_bits - 1;
	}

	bit_array_bytes = roundup(bit_array_bytes, sizeof(unsigned long));
	bloom_filter = bpf_map_area_alloc(sizeof(*bloom_filter) + bit_array_bytes,
					  numa_node);

	if (!bloom_filter)
		return ERR_PTR(-ENOMEM);

	bpf_map_init_from_attr(&bloom_filter->map, attr);
	bloom_filter->map.nr_hashes = attr->nr_hashes;

	bloom_filter->bit_array_mask = bit_array_mask;
	spin_lock_init(&bloom_filter->spinlock);

	if (!(attr->map_flags & BPF_F_ZERO_SEED))
		bloom_filter->hash_seed = get_random_int();

	return &bloom_filter->map;
}

static void bloom_filter_map_free(struct bpf_map *map)
{
	struct bpf_bloom_filter *bloom_filter =
		container_of(map, struct bpf_bloom_filter, map);

	bpf_map_area_free(bloom_filter);
}

static int bloom_filter_map_push_elem(struct bpf_map *map, void *value,
				      u64 flags)
{
	struct bpf_bloom_filter *bloom_filter =
		container_of(map, struct bpf_bloom_filter, map);
	unsigned long spinlock_flags;
	u32 i, hash;

	if (flags != BPF_ANY)
		return -EINVAL;

	spin_lock_irqsave(&bloom_filter->spinlock, spinlock_flags);

	for (i = 0; i < bloom_filter->map.nr_hashes; i++) {
		hash = jhash(value, map->value_size, bloom_filter->hash_seed + i) &
			bloom_filter->bit_array_mask;
		bitmap_set(bloom_filter->bit_array, hash, 1);
	}

	spin_unlock_irqrestore(&bloom_filter->spinlock, spinlock_flags);

	return 0;
}

static void *bloom_filter_map_lookup_elem(struct bpf_map *map, void *key)
{
	/* The eBPF program should use map_peek_elem instead */
	return ERR_PTR(-EINVAL);
}

static int bloom_filter_map_update_elem(struct bpf_map *map, void *key,
					void *value, u64 flags)
{
	/* The eBPF program should use map_push_elem instead */
	return -EINVAL;
}

static int bloom_filter_map_delete_elem(struct bpf_map *map, void *key)
{
	return -EOPNOTSUPP;
}

static int bloom_filter_map_get_next_key(struct bpf_map *map, void *key,
					 void *next_key)
{
	return -EOPNOTSUPP;
}

static int bloom_filter_map_btf_id;
const struct bpf_map_ops bloom_filter_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc = bloom_filter_map_alloc,
	.map_free = bloom_filter_map_free,
	.map_push_elem = bloom_filter_map_push_elem,
	.map_peek_elem = bloom_filter_map_peek_elem,
	.map_lookup_elem = bloom_filter_map_lookup_elem,
	.map_update_elem = bloom_filter_map_update_elem,
	.map_delete_elem = bloom_filter_map_delete_elem,
	.map_get_next_key = bloom_filter_map_get_next_key,
	.map_check_btf = map_check_no_btf,
	.map_btf_name = "bpf_bloom_filter",
	.map_btf_id = &bloom_filter_map_btf_id,
};
