// SPDX-License-Identifier: GPL-2.0
/*
 * Stringsets - a sorted set of strings
 *
 * Copyright (c) 2025, Oracle and/or its affiliates.
 * Author: Chuck Lever <chuck.lever@oracle.com>
 */

#include <linux/bug.h>
#include <linux/export.h>
#include <linux/sort.h>
#include <linux/string.h>
#include <linux/stringset.h>

static int stringset_cmp(const void *a, const void *b)
{
	const char * const *sa = a;
	const char * const *sb = b;

	return strcmp(*sa, *sb);
}

/**
 * stringset_finalize - Sort the stringset and remove duplicates
 * @set: An initialized stringset that has been populated
 *
 * This must be called after all strings have been added and before
 * calling stringset_is_member(), stringset_intersection(), or
 * stringset_copy(). Duplicate strings are removed and their memory
 * is freed.
 */
void stringset_finalize(struct stringset *set)
{
	unsigned int i, j;

	if (WARN_ON_ONCE(set->ss_finalized))
		return;
	if (set->ss_count > 1) {
		sort(set->ss_strings, set->ss_count, sizeof(char *),
		     stringset_cmp, NULL);

		for (i = 0, j = 1; j < set->ss_count; j++) {
			if (strcmp(set->ss_strings[i], set->ss_strings[j]) == 0)
				kfree(set->ss_strings[j]);
			else
				set->ss_strings[++i] = set->ss_strings[j];
		}
		set->ss_count = i + 1;
	}
	set->ss_finalized = true;
}
EXPORT_SYMBOL_GPL(stringset_finalize);

/**
 * stringset_destroy - Release stringset resources
 * @set: stringset to be destroyed
 */
void stringset_destroy(struct stringset *set)
{
	unsigned int i;

	for (i = 0; i < set->ss_count; i++)
		kfree(set->ss_strings[i]);
	kfree(set->ss_strings);
	stringset_init(set);
}
EXPORT_SYMBOL_GPL(stringset_destroy);

/**
 * stringset_is_member - Check if a string is already a member of a stringset
 * @set: An initialized and finalized stringset to be checked
 * @str: string to search for
 *
 * Uses binary search. The stringset must have been finalized first;
 * a query on an unfinalized stringset warns and returns %false.
 *
 * Return:
 * * %true: if @str is a member of @set
 * * %false: if @str is not a member of @set, or @set is not finalized
 */
bool stringset_is_member(const struct stringset *set, const char *str)
{
	unsigned int low = 0, high = set->ss_count;

	if (WARN_ON_ONCE(!set->ss_finalized))
		return false;
	/*
	 * Open-coded rather than bsearch() to call strcmp() directly,
	 * avoiding an indirect comparator call per search step.
	 */
	while (low < high) {
		unsigned int mid = low + (high - low) / 2;
		int cmp = strcmp(str, set->ss_strings[mid]);

		if (cmp == 0)
			return true;
		if (cmp < 0)
			high = mid;
		else
			low = mid + 1;
	}
	return false;
}
EXPORT_SYMBOL_GPL(stringset_is_member);

/**
 * stringset_copy - Duplicate strings to another stringset
 * @dest: An unallocated, initialized stringset to be filled
 * @src: An initialized, finalized stringset to be copied from
 * @gfp: Memory allocation flags
 *
 * @dest must be initialized -- via STRINGSET_INIT, DEFINE_STRINGSET,
 * stringset_init(), or a prior stringset_destroy() -- and must not yet
 * have storage allocated. An already-allocated @dest is a caller error:
 * the copy warns, frees @dest's storage, and returns failure.
 *
 * @src must be finalized: a copy reproduces @src's sorted, queryable
 * state, so copying an unfinalized stringset warns and returns failure.
 *
 * On success @dest is populated and ready for use; no call to
 * stringset_finalize() is required. On failure @dest is left as an
 * empty, finalized stringset, so callers can safely run queries
 * against it without first checking the return value.
 *
 * Return:
 * * %true: All strings in @src were copied to @dest
 * * %false: A failure occurred; @dest is empty and finalized
 */
bool stringset_copy(struct stringset *dest, const struct stringset *src, gfp_t gfp)
{
	unsigned int i;

	if (WARN_ON_ONCE(dest->ss_strings))
		goto out_fail;
	if (WARN_ON_ONCE(!src->ss_finalized))
		goto out_fail;
	if (src->ss_count && !stringset_alloc(dest, src->ss_count, gfp))
		goto out_fail;
	for (i = 0; i < src->ss_count; i++) {
		char *entry = kstrdup(src->ss_strings[i], gfp);

		if (!entry)
			goto out_fail;
		dest->ss_strings[dest->ss_count++] = entry;
	}
	/* src is finalized and thus sorted, so dest is too */
	dest->ss_finalized = true;
	return true;

out_fail:
	stringset_destroy(dest);
	dest->ss_finalized = true;
	return false;
}
EXPORT_SYMBOL_GPL(stringset_copy);

/**
 * stringset_intersection - Report if there are common strings
 * @set1: An initialized and finalized stringset
 * @set2: Another initialized and finalized stringset
 *
 * Uses merge-style comparison of two sorted arrays for O(N+M)
 * complexity. Both stringsets must have been finalized first; a
 * query on an unfinalized stringset warns and returns %false.
 *
 * Return:
 * * %true: @set1 and @set2 have at least one common string
 * * %false: @set1 and @set2 have no strings in common, or either
 *   stringset is not finalized
 */
bool stringset_intersection(const struct stringset *set1, const struct stringset *set2)
{
	unsigned int i = 0, j = 0;

	if (WARN_ON_ONCE(!set1->ss_finalized) ||
	    WARN_ON_ONCE(!set2->ss_finalized))
		return false;
	while (i < set1->ss_count && j < set2->ss_count) {
		int cmp = strcmp(set1->ss_strings[i], set2->ss_strings[j]);

		if (cmp == 0)
			return true;
		if (cmp < 0)
			i++;
		else
			j++;
	}
	return false;
}
EXPORT_SYMBOL_GPL(stringset_intersection);
