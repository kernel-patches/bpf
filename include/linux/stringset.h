/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Stringsets
 *
 * Copyright (c) 2025, Oracle and/or its affiliates.
 * Author: Chuck Lever <chuck.lever@oracle.com>
 *
 * A stringset is a set of strings. See
 * Documentation/core-api/stringset.rst for how to use stringsets.
 *
 * Stringsets have no internal locking. Callers synchronize writers
 * against readers, publish the finalized set with release/acquire
 * ordering, and drain readers before stringset_destroy(). See the
 * Thread Safety section of Documentation/core-api/stringset.rst.
 */

#ifndef _LINUX_STRINGSET_H
#define _LINUX_STRINGSET_H

#include <linux/bug.h>
#include <linux/slab.h>
#include <linux/string.h>

struct stringset {
	char		**ss_strings;
	unsigned int	ss_count;
	unsigned int	ss_capacity;
	bool		ss_finalized;
};

#define STRINGSET_INIT \
	{ .ss_strings = NULL, .ss_count = 0, .ss_capacity = 0, .ss_finalized = false }
#define DEFINE_STRINGSET(name) \
	struct stringset name = STRINGSET_INIT

/**
 * stringset_for_each - Iterate over items in a stringset
 * @set: An initialized stringset containing zero or more items
 * @index: Index counter for the iteration
 * @str: String retrieved from the stringset
 */
#define stringset_for_each(set, index, str) \
	for ((index) = 0; (index) < (set)->ss_count && \
	     ((str) = (set)->ss_strings[index], true); (index)++)

/**
 * stringset_init - Initialize an empty stringset
 * @set: stringset to be initialized
 */
static inline void stringset_init(struct stringset *set)
{
	set->ss_strings = NULL;
	set->ss_count = 0;
	set->ss_capacity = 0;
	set->ss_finalized = false;
}

/**
 * stringset_alloc - Pre-allocate space for strings
 * @set: An initialized stringset
 * @capacity: Number of strings to allocate space for
 * @gfp: Memory allocation flags
 *
 * This function allocates only once per stringset. Calling it on a
 * stringset that is already allocated returns failure. stringset_destroy()
 * releases the allocation, after which the stringset may be allocated
 * again.
 *
 * @capacity may be zero. The stringset then represents an empty set, and
 * stringset_add() rejects further additions. The same state is produced
 * by DEFINE_STRINGSET() and stringset_init() alone, so callers that know
 * the set is empty may skip stringset_alloc() entirely. An empty set
 * still goes through stringset_finalize() before stringset_is_member()
 * or stringset_intersection() can query it. A zero-capacity call allocates
 * nothing, so a later stringset_alloc() on the same set still succeeds.
 *
 * Return:
 * * %true: allocation succeeded (or @capacity was zero)
 * * %false: allocation failed or stringset already allocated
 */
static inline __must_check bool
stringset_alloc(struct stringset *set, unsigned int capacity, gfp_t gfp)
{
	if (set->ss_strings)
		return false;
	if (capacity == 0)
		return true;

	set->ss_strings = kcalloc(capacity, sizeof(char *), gfp);
	if (!set->ss_strings)
		return false;
	set->ss_capacity = capacity;
	return true;
}

/**
 * stringset_is_empty - Determine if a stringset contains any strings
 * @set: An initialized stringset to be checked
 *
 * Return:
 * * %true: if @set is empty
 * * %false: if @set contains one or more strings
 */
static inline bool stringset_is_empty(const struct stringset *set)
{
	return set->ss_count == 0;
}

/**
 * stringset_count - Return the number of strings in a stringset
 * @set: An initialized stringset to be checked
 *
 * If called before stringset_finalize(), returns the number of strings
 * added. If called after, returns the number of unique strings.
 *
 * Return:
 *    The number of strings in @set
 */
static inline unsigned int stringset_count(const struct stringset *set)
{
	return set->ss_count;
}

/**
 * stringset_add - Add a string to a stringset
 * @set: An initialized stringset with available capacity
 * @str: non-NULL string to be added to @set, in kmalloc'd memory
 *
 * On success, @str is now owned by @set and will be freed either
 * by stringset_finalize() (if a content duplicate) or stringset_destroy().
 * The stringset must have been allocated with sufficient capacity via
 * stringset_alloc(). Strings must not be added after stringset_finalize()
 * has been called. Callers must not hand the same pointer to stringset_add()
 * more than once: ownership has already transferred, and a second add
 * produces a double-free at stringset_destroy().
 *
 * Return:
 * * %true: @str is now a member of @set
 * * %false: @str could not be added (NULL, no capacity, or @set is
 *   already finalized)
 */
static inline __must_check bool
stringset_add(struct stringset *set, char *str)
{
	if (WARN_ON_ONCE(set->ss_finalized))
		return false;
	if (!str || set->ss_count >= set->ss_capacity)
		return false;
	set->ss_strings[set->ss_count++] = str;
	return true;
}

/**
 * stringset_add_dup - Add a copy of a string to a stringset
 * @set: An initialized stringset with available capacity
 * @str: non-NULL string to be copied and added to @set
 * @gfp: Memory allocation flags
 *
 * On success, @str will have been copied into a kmalloc'd
 * buffer. The caller can release @str immediately. Strings must not
 * be added after stringset_finalize() has been called.
 *
 * Return:
 * * %true: @str is now a member of @set
 * * %false: @str could not be added (NULL, no capacity, ENOMEM, or
 *   @set is already finalized)
 */
static inline __must_check bool
stringset_add_dup(struct stringset *set, const char *str, gfp_t gfp)
{
	char *entry;

	if (WARN_ON_ONCE(set->ss_finalized))
		return false;
	if (!str || set->ss_count >= set->ss_capacity)
		return false;
	entry = kstrdup(str, gfp);
	if (!entry)
		return false;
	set->ss_strings[set->ss_count++] = entry;
	return true;
}

/* Implemented in lib/stringset.c */
void stringset_finalize(struct stringset *set);
void stringset_destroy(struct stringset *set);
bool stringset_is_member(const struct stringset *set, const char *str);
bool stringset_copy(struct stringset *dest, const struct stringset *src, gfp_t gfp);
bool stringset_intersection(const struct stringset *set1, const struct stringset *set2);

#endif /* _LINUX_STRINGSET_H */
