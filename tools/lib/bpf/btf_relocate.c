// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024, Oracle and/or its affiliates. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "btf.h"
#include "bpf.h"
#include "libbpf.h"
#include "libbpf_internal.h"

struct btf;

struct btf_relocate {
	__u32 search_id;				/* must be first field; see search below */
	struct btf *btf;
	const struct btf *base_btf;
	const struct btf *dist_base_btf;
	unsigned int nr_base_types;
	unsigned int nr_split_types;
	unsigned int nr_dist_base_types;
	int str_start;
	int str_diff;
	__u32 *map;
	__u32 *str_map;
	__u32 *dist_base_index;
};

static int btf_relocate_rewrite_type_id(__u32 *id, void *ctx)
{
	struct btf_relocate *r = ctx;

	*id = r->map[*id];
	return 0;
}

/* Simple string comparison used for sorting within BTF, since all distilled types are
 * named.
 */
static int cmp_btf_types(const void *id1, const void *id2, void *priv)
{
	const struct btf *btf = priv;
	const struct btf_type *t1 = btf_type_by_id(btf, *(__u32 *)id1);
	const struct btf_type *t2 = btf_type_by_id(btf, *(__u32 *)id2);

	return strcmp(btf__name_by_offset(btf, t1->name_off),
		      btf__name_by_offset(btf, t2->name_off));
}

/* Comparison between base BTF type (search type) and distilled base types (target).
 * Because there is no bsearch_r() we need to use the search key - which also is
 * the first element of struct btf_relocate * - as a means to retrieve the
 * struct btf_relocate *.
 */
static int cmp_base_and_distilled_btf_types(const void *idbase, const void *iddist)
{
	struct btf_relocate *r = (struct btf_relocate *)idbase;
	const struct btf_type *tbase = btf_type_by_id(r->base_btf, *(__u32 *)idbase);
	const struct btf_type *tdist = btf_type_by_id(r->dist_base_btf, *(__u32 *)iddist);

	return strcmp(btf__name_by_offset(r->base_btf, tbase->name_off),
		      btf__name_by_offset(r->dist_base_btf, tdist->name_off));
}

/* Build a map from distilled base BTF ids to base BTF ids. To do so, iterate
 * through base BTF looking up distilled type (using binary search) equivalents.
 */
static int btf_relocate_map_distilled_base(struct btf_relocate *r)
{
	struct btf_type *t;
	const char *name;
	__u32 id;

	/* generate a sort index array of type ids sorted by name for distilled
	 * base BTF to speed lookups.
	 */
	for (id = 1; id < r->nr_dist_base_types; id++)
		r->dist_base_index[id] = id;
	qsort_r(r->dist_base_index, r->nr_dist_base_types, sizeof(__u32), cmp_btf_types,
		(struct btf *)r->dist_base_btf);

	for (id = 1; id < r->nr_base_types; id++) {
		struct btf_type *dist_t;
		int dist_kind, kind;
		bool compat_kind;
		__u32 *dist_id;

		t = btf_type_by_id(r->base_btf, id);
		kind = btf_kind(t);
		/* distilled base consists of named types only. */
		if (!t->name_off)
			continue;
		switch (kind) {
		case BTF_KIND_INT:
		case BTF_KIND_FLOAT:
		case BTF_KIND_ENUM:
		case BTF_KIND_ENUM64:
		case BTF_KIND_FWD:
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
			break;
		default:
			continue;
		}
		r->search_id = id;
		dist_id = bsearch(&r->search_id, r->dist_base_index, r->nr_dist_base_types,
				  sizeof(__u32), cmp_base_and_distilled_btf_types);
		if (!dist_id)
			continue;
		if (!*dist_id || *dist_id > r->nr_dist_base_types) {
			pr_warn("base BTF id [%d] maps to invalid distilled base BTF id [%d]\n",
				id, *dist_id);
			return -EINVAL;
		}
		/* validate that kinds are compatible */
		dist_t = btf_type_by_id(r->dist_base_btf, *dist_id);
		dist_kind = btf_kind(dist_t);
		name = btf__name_by_offset(r->dist_base_btf, dist_t->name_off);
		compat_kind = dist_kind == kind;
		if (!compat_kind) {
			switch (dist_kind) {
			case BTF_KIND_FWD:
				compat_kind = kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION;
				break;
			case BTF_KIND_ENUM:
				compat_kind = kind == BTF_KIND_ENUM64;
				break;
			default:
				break;
			}
			if (!compat_kind) {
				pr_warn("kind incompatibility (%d != %d) between distilled base type '%s'[%d] and base type [%d]\n",
					dist_kind, kind, name, *dist_id, id);
				return -EINVAL;
			}
		}
		/* validate that int, float struct, union sizes are compatible;
		 * distilled base BTF encodes an empty STRUCT/UNION with
		 * specific size for cases where a type is embedded in a split
		 * type (so has to preserve size info).  Do not error out
		 * on mismatch as another size match may occur for an
		 * identically-named type.
		 */
		switch (btf_kind(dist_t)) {
		case BTF_KIND_INT:
			if (*(__u32 *)(t + 1) != *(__u32 *)(dist_t + 1))
				continue;
			if (t->size != dist_t->size)
				continue;
			break;
		case BTF_KIND_FLOAT:
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
			if (t->size != dist_t->size)
				continue;
			break;
		default:
			break;
		}
		/* map id and name */
		r->map[*dist_id] = id;
		r->str_map[dist_t->name_off] = t->name_off;
	}
	/* ensure all distilled BTF ids have a mapping... */
	for (id = 1; id < r->nr_dist_base_types; id++) {
		if (r->map[id])
			continue;
		t = btf_type_by_id(r->dist_base_btf, id);
		name = btf__name_by_offset(r->dist_base_btf, t->name_off);
		pr_warn("distilled base BTF type '%s' [%d] is not mapped to base BTF id\n",
			name, id);
		return -EINVAL;
	}
	return 0;
}

/* distilled base should only have named int/float/enum/fwd/struct/union types. */
static int btf_relocate_validate_distilled_base(struct btf_relocate *r)
{
	unsigned int i;

	for (i = 1; i < r->nr_dist_base_types; i++) {
		struct btf_type *t = btf_type_by_id(r->dist_base_btf, i);
		int kind = btf_kind(t);

		switch (kind) {
		case BTF_KIND_INT:
		case BTF_KIND_FLOAT:
		case BTF_KIND_ENUM:
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
		case BTF_KIND_FWD:
			if (t->name_off)
				break;
			pr_warn("type [%d], kind [%d] is invalid for distilled base BTF; it is anonymous\n",
				i, kind);
			return -EINVAL;
		default:
			pr_warn("type [%d] in distilled based BTF has unexpected kind [%d]\n",
				i, kind);
			return -EINVAL;
		}
	}
	return 0;
}

static int btf_rewrite_strs(__u32 *str_off, void *ctx)
{
	struct btf_relocate *r = ctx;
	int off;

	if (!*str_off)
		return 0;
	if (*str_off >= r->str_start) {
		*str_off += r->str_diff;
	} else {
		off = r->str_map[*str_off];
		if (!off) {
			pr_warn("string '%s' [offset %d] is not mapped to base BTF",
				btf__str_by_offset(r->btf, off), *str_off);
			return -ENOENT;
		}
		*str_off = off;
	}
	return 0;
}

static int btf_relocate_finalize(struct btf_relocate *r)
{
	const struct btf_header *dist_base_hdr;
	const struct btf_header *base_hdr;
	struct btf_type *t;
	int i, err;

	dist_base_hdr = btf_header(r->dist_base_btf);
	base_hdr = btf_header(r->base_btf);
	r->str_start = dist_base_hdr->str_len;
	r->str_diff = base_hdr->str_len - dist_base_hdr->str_len;
	for (i = 0; i < r->nr_split_types; i++) {
		t = btf_type_by_id(r->btf, i + r->nr_dist_base_types);
		err = btf_type_visit_str_offs(t, btf_rewrite_strs, r);
		if (err)
			break;
	}
	btf_set_base_btf(r->btf, r->base_btf);

	return err;
}

/* If successful, output of relocation is updated BTF with base BTF pointing
 * at base_btf, and type ids, strings adjusted accordingly
 */
int btf_relocate(struct btf *btf, const struct btf *base_btf, __u32 **map_ids)
{
	unsigned int nr_types = btf__type_cnt(btf);
	struct btf_relocate r = {};
	struct btf_type *t;
	int diff_id, err = 0;
	__u32 id, i;

	r.dist_base_btf = btf__base_btf(btf);
	if (!base_btf || r.dist_base_btf == base_btf)
		return 0;

	r.nr_dist_base_types = btf__type_cnt(r.dist_base_btf);
	r.nr_base_types = btf__type_cnt(base_btf);
	r.nr_split_types = nr_types - r.nr_dist_base_types;
	r.btf = btf;
	r.base_btf = base_btf;

	r.map = calloc(nr_types, sizeof(*r.map));
	r.str_map = calloc(btf_header(r.dist_base_btf)->str_len, sizeof(*r.str_map));
	r.dist_base_index = calloc(r.nr_dist_base_types, sizeof(*r.dist_base_index));
	if (!r.map || !r.str_map || !r.dist_base_index) {
		err = -ENOMEM;
		goto err_out;
	}

	err = btf_relocate_validate_distilled_base(&r);
	if (err)
		goto err_out;

	diff_id = r.nr_base_types - r.nr_dist_base_types;
	/* Split BTF ids will start from after last base BTF id. */
	for (id = r.nr_dist_base_types; id < nr_types; id++)
		r.map[id] = id + diff_id;

	/* Build a map from distilled base ids to actual base BTF ids; it is used
	 * to update split BTF id references.
	 */
	err = btf_relocate_map_distilled_base(&r);
	if (err)
		goto err_out;

	/* Next, rewrite type ids in split BTF, replacing split ids with updated
	 * ids based on number of types in base BTF, and base ids with
	 * relocated ids from base_btf.
	 */
	for (i = 0, id = r.nr_dist_base_types; i < r.nr_split_types; i++, id++) {
		t = btf_type_by_id(btf, id);
		err = btf_type_visit_type_ids(t, btf_relocate_rewrite_type_id, &r);
		if (err)
			goto err_out;
	}
	/* Finally reset base BTF to base_btf; as part of this operation, string
	 * offsets are also updated, and we are done.
	 */
	err = btf_relocate_finalize(&r);
err_out:
	if (!err && map_ids)
		*map_ids = r.map;
	else
		free(r.map);
	free(r.str_map);
	free(r.dist_base_index);
	return err;
}
