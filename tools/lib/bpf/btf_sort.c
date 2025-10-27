// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Xiaomi */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef __KERNEL__

#define btf_type_by_id				(struct btf_type *)btf_type_by_id
#define btf__str_by_offset			btf_str_by_offset
#define btf__type_cnt				btf_nr_types
#define btf__start_id				btf_start_id
#define libbpf_err(x)				x

#else

#define notrace

#endif /* __KERNEL__ */

/*
 * Skip the sorted check if the number of BTF types is below this threshold.
 * The value 4 is chosen based on the theoretical break-even point where
 * linear search (N/2) and binary search (LOG2(N)) require approximately
 * the same number of comparisons.
 */
#define BTF_CHECK_SORT_THRESHOLD  4

struct btf;

static int cmp_btf_kind_name(int ka, const char *na, int kb, const char *nb)
{
	return (ka - kb) ?: strcmp(na, nb);
}

/*
 * Sort BTF types by kind and name in ascending order, placing named types
 * before anonymous ones.
 */
static int btf_compare_type_kinds_names(const void *a, const void *b, void *priv)
{
	struct btf *btf = (struct btf *)priv;
	struct btf_type *ta = btf_type_by_id(btf, *(__u32 *)a);
	struct btf_type *tb = btf_type_by_id(btf, *(__u32 *)b);
	const char *na, *nb;
	bool anon_a, anon_b;
	int ka, kb;

	na = btf__str_by_offset(btf, ta->name_off);
	nb = btf__str_by_offset(btf, tb->name_off);
	anon_a = str_is_empty(na);
	anon_b = str_is_empty(nb);

	/* ta w/o name is greater than tb */
	if (anon_a && !anon_b)
		return 1;
	/* tb w/o name is smaller than ta */
	if (!anon_a && anon_b)
		return -1;

	ka = btf_kind(ta);
	kb = btf_kind(tb);

	if (anon_a && anon_b)
		return ka - kb;

	return cmp_btf_kind_name(ka, na, kb, nb);
}

static __s32 notrace __btf_find_by_name_kind(const struct btf *btf, int start_id,
				   const char *type_name, __u32 kind)
{
	const struct btf_type *t;
	const char *tname;
	int err = -ENOENT;

	if (!btf)
		goto out;

	if (start_id < btf__start_id(btf)) {
		err = __btf_find_by_name_kind(btf->base_btf, start_id, type_name, kind);
		if (err == -ENOENT)
			start_id = btf__start_id(btf);
	}

	if (err == -ENOENT) {
		if (btf->nr_sorted_types) {
			/* binary search */
			__s32 start, end, mid, found = -1;
			int ret;

			start = start_id;
			end = start + btf->nr_sorted_types - 1;
			/* found the leftmost btf_type that matches */
			while(start <= end) {
				mid = start + (end - start) / 2;
				t = btf_type_by_id(btf, mid);
				tname = btf__str_by_offset(btf, t->name_off);
				ret = cmp_btf_kind_name(BTF_INFO_KIND(t->info), tname,
							kind, type_name);
				if (ret < 0)
					start = mid + 1;
				else {
					if (ret == 0)
						found = mid;
					end = mid - 1;
				}
			}

			if (found != -1)
				return found;
		} else {
			/* linear search */
			__u32 i, total;

			total = btf__type_cnt(btf);
			for (i = start_id; i < total; i++) {
				t = btf_type_by_id(btf, i);
				if (btf_kind(t) != kind)
					continue;

				tname = btf__str_by_offset(btf, t->name_off);
				if (tname && !strcmp(tname, type_name))
					return i;
			}
		}
	}

out:
	return err;
}

/* start_id specifies the starting BTF to search */
static __s32 notrace _btf_find_by_name_kind(const struct btf *btf, int start_id,
				   const char *type_name, __u32 kind)
{
	if (kind == BTF_KIND_UNKN || !strcmp(type_name, "void"))
		return 0;

	return libbpf_err(__btf_find_by_name_kind(btf, start_id, type_name, kind));
}

static void btf_check_sorted(struct btf *btf, int start_id)
{
	const struct btf_type *t;
	int i, n, nr_sorted_types;

	n = btf__type_cnt(btf);
	if (btf->nr_types < BTF_CHECK_SORT_THRESHOLD)
		return;

	n--;
	nr_sorted_types = 0;
	for (i = start_id; i < n; i++) {
		int k = i + 1;

		if (btf_compare_type_kinds_names(&i, &k, btf) > 0)
			return;

		t = btf_type_by_id(btf, k);
		if (!str_is_empty(btf__str_by_offset(btf, t->name_off)))
			nr_sorted_types++;
	}

	t = btf_type_by_id(btf, start_id);
	if (!str_is_empty(btf__str_by_offset(btf, t->name_off)))
		nr_sorted_types++;

	if (nr_sorted_types < BTF_CHECK_SORT_THRESHOLD)
		return;

	btf->nr_sorted_types = nr_sorted_types;
}
