// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef __KERNEL__
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/string.h>

#define btf_type_by_id				(struct btf_type *)btf_type_by_id
#define btf__str_by_offset			btf_str_by_offset
#define btf__name_by_offset			btf_name_by_offset
#define btf__type_cnt				btf_nr_types
#define btf__start_id				btf_start_id
#define btf__nr_sorted_types			btf_nr_sorted_types
#define btf__set_nr_sorted_types		btf_set_nr_sorted_types
#define btf__base_btf				btf_base_btf
#define libbpf_err(x)				x

#else

#include "btf.h"
#include "bpf.h"
#include "libbpf.h"
#include "libbpf_internal.h"

#endif /* __KERNEL__ */

/* Skip the sorted check if number of btf_types is below threshold
 */
#define BTF_CHECK_SORT_THRESHOLD  8

struct btf;

static int cmp_btf_kind_name(int ka, const char *na, int kb, const char *nb)
{
	return (ka - kb) ?: strcmp(na, nb);
}

/*
 * Sort BTF types by kind and name in ascending order, placing named types
 * before anonymous ones.
 */
int btf_compare_type_kinds_names(const void *a, const void *b, void *priv)
{
	struct btf *btf = (struct btf *)priv;
	struct btf_type *ta = btf_type_by_id(btf, *(__u32 *)a);
	struct btf_type *tb = btf_type_by_id(btf, *(__u32 *)b);
	const char *na, *nb;
	int ka, kb;

	/* ta w/o name is greater than tb */
	if (!ta->name_off && tb->name_off)
		return 1;
	/* tb w/o name is smaller than ta */
	if (ta->name_off && !tb->name_off)
		return -1;

	ka = btf_kind(ta);
	kb = btf_kind(tb);
	na = btf__str_by_offset(btf, ta->name_off);
	nb = btf__str_by_offset(btf, tb->name_off);

	return cmp_btf_kind_name(ka, na, kb, nb);
}

__s32 find_btf_by_name_kind(const struct btf *btf, int start_id,
				   const char *type_name, __u32 kind)
{
	const struct btf_type *t;
	const char *tname;
	__u32 i, total;

	if (kind == BTF_KIND_UNKN || !strcmp(type_name, "void"))
		return 0;

	do {
		if (btf__nr_sorted_types(btf)) {
			/* binary search */
			__s32 start, end, mid, found = -1;
			int ret;

			start = btf__start_id(btf);
			end = start + btf__nr_sorted_types(btf) - 1;
			/* found the leftmost btf_type that matches */
			while(start <= end) {
				mid = start + (end - start) / 2;
				t = btf_type_by_id(btf, mid);
				tname = btf__name_by_offset(btf, t->name_off);
				ret = cmp_btf_kind_name(BTF_INFO_KIND(t->info), tname,
							kind, type_name);
				if (ret == 0)
					found = mid;
				if (ret < 0)
					start = mid + 1;
				else if (ret >= 0)
					end = mid - 1;
			}

			if (found != -1)
				return found;
		} else {
			/* linear search */
			total = btf__type_cnt(btf);
			for (i = btf__start_id(btf); i < total; i++) {
				t = btf_type_by_id(btf, i);
				if (btf_kind(t) != kind)
					continue;

				tname = btf__name_by_offset(btf, t->name_off);
				if (tname && !strcmp(tname, type_name))
					return i;
			}
		}

		btf = btf__base_btf(btf);
	} while (btf && btf__start_id(btf) >= start_id);

	return libbpf_err(-ENOENT);
}

void btf_check_sorted(struct btf *btf, int start_id)
{
	const struct btf_type *t;
	int i, n, nr_sorted_types;

	n = btf__type_cnt(btf);
	if ((n - start_id) < BTF_CHECK_SORT_THRESHOLD)
		return;

	n--;
	nr_sorted_types = 0;
	for (i = start_id; i < n; i++) {
		int k = i + 1;

		t = btf_type_by_id(btf, i);
		if (!btf__str_by_offset(btf, t->name_off))
			return;

		t = btf_type_by_id(btf, k);
		if (!btf__str_by_offset(btf, t->name_off))
			return;

		if (btf_compare_type_kinds_names(&i, &k, btf) > 0)
			return;

		if (t->name_off)
			nr_sorted_types++;
	}

	t = btf_type_by_id(btf, start_id);
	if (t->name_off)
		nr_sorted_types++;
	if (nr_sorted_types >= BTF_CHECK_SORT_THRESHOLD)
		btf__set_nr_sorted_types(btf, nr_sorted_types);
}

