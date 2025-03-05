/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2025 Arthur Fabre, Cloudflare */
#ifndef __LINUX_NET_TRAIT_H__
#define __LINUX_NET_TRAIT_H__

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/bitops.h>

/* Traits are a very limited KV store, with:
 * - 64 keys (0-63).
 * - 2, 4 or 8 byte values.
 * - O(1) lookup
 * - O(n) insertion
 * - A fixed 16 byte header.
 */
struct __trait_hdr {
	/* Values are stored ordered by key, immediately after the header.
	 *
	 * The size of each value set is stored in the header as two bits:
	 *  - 00: Not set.
	 *  - 01: 2 bytes.
	 *  - 10: 4 bytes.
	 *  - 11: 8 bytes.
	 *
	 * Naively storing the size of each value (eg packing 4 of them in a byte)
	 * doesn't let us efficiently calculate the offset of the value of an arbitrary key:
	 * we'd have to mask out and sum the sizes of all preceding values.
	 *
	 * Instead, store the high and low bits of the size in two separate words:
	 *  - A high bit in the high word.
	 *  - A low bit in the low word.
	 * The bit position of each word, LSb 0, is the key.
	 *
	 * To calculate the offset of the value of a key:
	 *  - Mask out subsequent keys from both words.
	 *  - Calculate the hamming weight / population count of each word.
	 *    Single instruction on modern amd64 CPUs.
	 *  - hweight(low) + hweight(high)<<1 is offset.
	 */
	u64 high;
	u64 low;
};

static __always_inline bool __trait_valid_len(u64 len)
{
	return len == 2 || len == 4 || len == 8;
}

static __always_inline bool __trait_valid_key(u64 key)
{
	return key < 64;
}

static __always_inline int __trait_total_length(struct __trait_hdr h)
{
	return (hweight64(h.low) << 1) + (hweight64(h.high) << 2)
		// For size 8, we only get 4+2=6. Add another 2 in.
		+ (hweight64(h.high & h.low) << 1);
}

static __always_inline struct __trait_hdr __trait_and(struct __trait_hdr h, u64 mask)
{
	return (struct __trait_hdr){
		h.high & mask,
		h.low & mask,
	};
}

static __always_inline int __trait_offset(struct __trait_hdr h, u64 key)
{
	/* Calculate total length of previous keys by masking out keys after. */
	return sizeof(struct __trait_hdr) + __trait_total_length(__trait_and(h, ~(~0llu << key)));
}

/**
 * traits_init() - Initialize a trait store.
 * @traits: Start of trait store area.
 * @hard_end: Hard limit the trait store can currently grow up against.
 *            Can change dynamically after initialization, as long as it
 *            does not overwrite any area already used (see traits_size()).
 *
 * Return:
 * * %0       - Success.
 * * %-ENOMEM - Not enough room to store any traits.
 */
static __always_inline int traits_init(void *traits, void *hard_end)
{
	if (traits + sizeof(struct __trait_hdr) > hard_end)
		return -ENOMEM;

	memset(traits, 0, sizeof(struct __trait_hdr));
	return 0;
}

/**
 * traits_size() - Total size currently used by a trait store.
 * @traits: Start of trait store area.
 *
 * Return: Size in bytes.
 */
static __always_inline int traits_size(void *traits)
{
	return sizeof(struct __trait_hdr) + __trait_total_length(*(struct __trait_hdr *)traits);
}

/**
 * trait_set() - Set a trait key.
 * @traits: Start of trait store area.
 * @hard_end: Hard limit the trait store can currently grow up against.
 * @key: The key to set.
 * @val: The value to set.
 * @len: The length of the value.
 * @flags: Unused for now. Should be 0.
 *
 * Return:
 * * %0       - Success.
 * * %-EINVAL - Key or length invalid.
 * * %-EBUSY  - Key previously set with different length.
 * * %-ENOSPC - Not enough room left to store value.
 */
static __always_inline
int trait_set(void *traits, void *hard_end, u64 key, const void *val, u64 len, u64 flags)
{
	if (!__trait_valid_key(key) || !__trait_valid_len(len))
		return -EINVAL;

	struct __trait_hdr *h = (struct __trait_hdr *)traits;

	/* Offset of value of this key. */
	int off = __trait_offset(*h, key);

	if ((h->high & (1ull << key)) || (h->low & (1ull << key))) {
		/* Key is already set, but with a different length */
		if (__trait_total_length(__trait_and(*h, (1ull << key))) != len)
			return -EBUSY;
	} else {
		/* Figure out if we have enough room left: total length of everything now. */
		if (traits + sizeof(struct __trait_hdr) + __trait_total_length(*h) + len > hard_end)
			return -ENOSPC;

		/* Memmove all the kvs after us over. */
		if (traits_size(traits) > off)
			memmove(traits + off + len, traits + off, traits_size(traits) - off);
	}

	/* Set our value. */
	memcpy(traits + off, val, len);

	/* Store our length in header. */
	u64 encode_len = 0;

	switch (len) {
	case 2:
		encode_len = 1;
		break;
	case 4:
		encode_len = 2;
		break;
	case 8:
		encode_len = 3;
		break;
	}
	h->high |= (encode_len >> 1) << key;
	h->low |= (encode_len & 1) << key;
	return 0;
}

/**
 * trait_get() - Get a trait key.
 * @traits: Start of trait store area.
 * @key: The key to get.
 * @val: Where to put stored value.
 * @val_len: The length of val.
 *
 * Return:
 * * %>0      - Actual size of value.
 * * %-EINVAL - Key or length invalid.
 * * %-ENOENT - Key has not been set with trait_set() previously.
 * * %-ENOSPC - Val is not big enough to hold stored value.
 */
static __always_inline
int trait_get(void *traits, u64 key, void *val, u64 val_len)
{
	if (!__trait_valid_key(key))
		return -EINVAL;

	struct __trait_hdr h = *(struct __trait_hdr *)traits;

	/* Check key is set */
	if (!((h.high & (1ull << key)) || (h.low & (1ull << key))))
		return -ENOENT;

	/* Offset of value of this key */
	int off = __trait_offset(h, key);

	/* Figure out our length */
	int real_len = __trait_total_length(__trait_and(h, (1ull << key)));

	if (real_len > val_len)
		return -ENOSPC;

	memcpy(val, traits + off, real_len);
	return real_len;
}

/**
 * trait_del() - Delete a trait key.
 * @traits: Start of trait store area.
 * @key: The key to delete.
 *
 * Return:
 * * %0       - Success.
 * * %-EINVAL - Key or length invalid.
 * * %-ENOENT - Key has not been set with trait_set() previously.
 */
static __always_inline int trait_del(void *traits, u64 key)
{
	if (!__trait_valid_key(key))
		return -EINVAL;

	struct __trait_hdr *h = (struct __trait_hdr *)traits;

	/* Check key is set */
	if (!((h->high & (1ull << key)) || (h->low & (1ull << key))))
		return -ENOENT;

	/* Offset and length of value of this key */
	int off = __trait_offset(*h, key);
	int len = __trait_total_length(__trait_and(*h, (1ull << key)));

	/* Memmove all the kvs after us over */
	if (traits_size(traits) > off + len)
		memmove(traits + off, traits + off + len, traits_size(traits) - off - len);

	/* Clear our length in header */
	h->high &= ~(1ull << key);
	h->low &= ~(1ull << key);
	return 0;
}

#endif /* __LINUX_NET_TRAIT_H__ */
