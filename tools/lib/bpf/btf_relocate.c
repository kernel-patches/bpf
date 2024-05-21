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
	struct btf *btf;
	const struct btf *base_btf;
	const struct btf *dist_base_btf;
	unsigned int nr_base_types;
	unsigned int nr_split_types;
	unsigned int nr_dist_base_types;
	int dist_str_len;
	int base_str_len;
	__u32 *id_map;
	__u32 *str_map;
};

/* Set temporarily in relocation id_map if distilled base struct/union is
 * embedded in a split BTF struct/union; in such a case, size information must
 * match between distilled base BTF and base BTF representation of type.
 */
#define BTF_IS_EMBEDDED ((__u32)-1)

/* <name, size, id> triple used in sorting/searching distilled base BTF. */
struct btf_name_info {
	const char *name;
	__u32 size;
	__u32 id;
};

static int btf_relocate_rewrite_type_id(__u32 *id, void *ctx)
{
	struct btf_relocate *r = ctx;

	*id = r->id_map[*id];
	return 0;
}

/* Simple string comparison used for sorting within BTF, since all distilled
 * types are named.  If strings match, and size is non-zero for both elements
 * fall back to using size for ordering.
 */
static int cmp_btf_name_size(const void *n1, const void *n2)
{
	const struct btf_name_info *ni1 = n1;
	const struct btf_name_info *ni2 = n2;
	int name_diff = strcmp(ni1->name, ni2->name);

	if (!name_diff && ni1->size && ni2->size)
		return ni2->size - ni1->size;
	return name_diff;
}

/* If a member of a split BTF struct/union refers to a base BTF
 * struct/union, mark that struct/union id temporarily in the id_map
 * with BTF_IS_EMBEDDED.  Members can be const/restrict/volatile/typedef
 * reference types, but if a pointer is encountered, the type is no longer
 * considered embedded.
 */
static int btf_mark_embedded_composite_type_ids(__u32 *id, void *ctx)
{
	struct btf_relocate *r = ctx;
	struct btf_type *t;
	__u32 next_id = *id;

	while (true) {
		if (next_id == 0)
			return 0;
		t = btf_type_by_id(r->btf, next_id);
		switch (btf_kind(t)) {
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_TYPE_TAG:
			next_id = t->type;
			break;
		case BTF_KIND_ARRAY: {
			struct btf_array *a = btf_array(t);

			next_id = a->type;
			break;
		}
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
			if (next_id < r->nr_dist_base_types)
				r->id_map[next_id] = BTF_IS_EMBEDDED;
			return 0;
		default:
			return 0;
		}
	}

	return 0;
}

/* Build a map from distilled base BTF ids to base BTF ids. To do so, iterate
 * through base BTF looking up distilled type (using binary search) equivalents.
 */
static int btf_relocate_map_distilled_base(struct btf_relocate *r)
{
	struct btf_name_info *dist_base_info_sorted;
	struct btf_type *base_t, *dist_t, *split_t;
	__u8 *base_name_cnt = NULL;
	int err = 0;
	__u32 id;

	/* generate a sort index array of name/type ids sorted by name for
	 * distilled base BTF to speed name-based lookups.
	 */
	dist_base_info_sorted = calloc(r->nr_dist_base_types, sizeof(*dist_base_info_sorted));
	if (!dist_base_info_sorted) {
		err = -ENOMEM;
		goto done;
	}
	for (id = 0; id < r->nr_dist_base_types; id++) {
		dist_t = btf_type_by_id(r->dist_base_btf, id);
		dist_base_info_sorted[id].name = btf__name_by_offset(r->dist_base_btf,
								     dist_t->name_off);
		dist_base_info_sorted[id].id = id;
		dist_base_info_sorted[id].size = dist_t->size;
	}
	qsort(dist_base_info_sorted, r->nr_dist_base_types, sizeof(*dist_base_info_sorted),
	      cmp_btf_name_size);

	/* Mark distilled base struct/union members of split BTF structs/unions
	 * in id_map with BTF_IS_EMBEDDED; this signals that these types
	 * need to match both name and size, otherwise embeddding the base
	 * struct/union in the split type is invalid.
	 */
	for (id = r->nr_dist_base_types; id < r->nr_split_types; id++) {
		split_t = btf_type_by_id(r->btf, id);
		if (btf_is_composite(split_t)) {
			err = btf_type_visit_type_ids(split_t, btf_mark_embedded_composite_type_ids,
						      r);
			if (err < 0)
				goto done;
		}
	}

	/* Collect name counts for composite types in base BTF.  If multiple
	 * instances of a struct/union of the same name exist, we need to use
	 * size to determine which to map to since name alone is ambiguous.
	 */
	base_name_cnt = calloc(r->base_str_len, sizeof(*base_name_cnt));
	if (!base_name_cnt) {
		err = -ENOMEM;
		goto done;
	}
	for (id = 1; id < r->nr_base_types; id++) {
		base_t = btf_type_by_id(r->base_btf, id);
		if (!btf_is_composite(base_t) || !base_t->name_off)
			continue;
		if (base_name_cnt[base_t->name_off] < 255)
			base_name_cnt[base_t->name_off]++;
	}

	/* Now search base BTF for matching distilled base BTF types. */
	for (id = 1; id < r->nr_base_types; id++) {
		struct btf_name_info *dist_name_info, base_name_info = {};
		int dist_kind, base_kind;

		base_t = btf_type_by_id(r->base_btf, id);
		/* distilled base consists of named types only. */
		if (!base_t->name_off)
			continue;
		base_kind = btf_kind(base_t);
		base_name_info.id = id;
		base_name_info.name = btf__name_by_offset(r->base_btf, base_t->name_off);

		switch (base_kind) {
		case BTF_KIND_INT:
		case BTF_KIND_FLOAT:
		case BTF_KIND_ENUM:
		case BTF_KIND_ENUM64:
			/* These types should match both name and size */
			base_name_info.size = base_t->size;
			break;
		case BTF_KIND_FWD:
			/* No size considerations for fwds. */
			break;
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
			/* Size only needs to be used for struct/union if there
			 * are multiple types in base BTF with the same name.
			 * If there are multiple _distilled_ types with the same
			 * name (a very unlikely scenario), that doesn't matter
			 * unless there are not multiple _base_ types to match
			 * them.
			 */
			if (base_name_cnt[base_t->name_off] > 1)
				base_name_info.size = base_t->size;
			break;
		default:
			continue;
		}
		dist_name_info = bsearch(&base_name_info, dist_base_info_sorted,
					 r->nr_dist_base_types, sizeof(*dist_base_info_sorted),
					 cmp_btf_name_size);
		if (!dist_name_info)
			continue;
		if (!dist_name_info->id || dist_name_info->id > r->nr_dist_base_types) {
			pr_warn("base BTF id [%d] maps to invalid distilled base BTF id [%d]\n",
				id, dist_name_info->id);
			err = -EINVAL;
			goto done;
		}
		dist_t = btf_type_by_id(r->dist_base_btf, dist_name_info->id);
		dist_kind = btf_kind(dist_t);

		/* Validate that the found distilled type is compatible.
		 * Do not error out on mismatch as another match may occur
		 * for an identically-named type.
		 */
		switch (dist_kind) {
		case BTF_KIND_FWD:
			switch (base_kind) {
			case BTF_KIND_FWD:
				if (btf_kflag(dist_t) != btf_kflag(base_t))
					continue;
				break;
			case BTF_KIND_STRUCT:
				if (btf_kflag(base_t))
					continue;
				break;
			case BTF_KIND_UNION:
				if (!btf_kflag(base_t))
					continue;
				break;
			default:
				continue;
			}
			break;
		case BTF_KIND_INT:
			if (dist_kind != base_kind ||
			    btf_int_encoding(base_t) != btf_int_encoding(dist_t))
				continue;
			break;
		case BTF_KIND_FLOAT:
			if (dist_kind != base_kind)
				continue;
			break;
		case BTF_KIND_ENUM:
			/* ENUM and ENUM64 are encoded as sized ENUM in
			 * distilled base BTF.
			 */
			if (dist_kind != base_kind && base_kind != BTF_KIND_ENUM64)
				continue;
			break;
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
			/* size verification is required for embedded
			 * struct/unions.
			 */
			if (r->id_map[dist_name_info->id] == BTF_IS_EMBEDDED &&
			    base_t->size != dist_t->size)
				continue;
			break;
		default:
			continue;
		}
		/* map id and name */
		r->id_map[dist_name_info->id] = id;
		r->str_map[dist_t->name_off] = base_t->name_off;
	}
	/* ensure all distilled BTF ids now have a mapping... */
	for (id = 1; id < r->nr_dist_base_types; id++) {
		const char *name;

		if (r->id_map[id] && r->id_map[id] != BTF_IS_EMBEDDED)
			continue;
		dist_t = btf_type_by_id(r->dist_base_btf, id);
		name = btf__name_by_offset(r->dist_base_btf, dist_t->name_off);
		pr_warn("distilled base BTF type '%s' [%d] is not mapped to base BTF id\n",
			name, id);
		err = -EINVAL;
		break;
	}
done:
	free(base_name_cnt);
	free(dist_base_info_sorted);
	return err;
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

static int btf_relocate_rewrite_strs(__u32 *str_off, void *ctx)
{
	struct btf_relocate *r = ctx;
	int off;

	if (!*str_off)
		return 0;
	if (*str_off >= r->dist_str_len) {
		*str_off += r->base_str_len - r->dist_str_len;
	} else {
		off = r->str_map[*str_off];
		if (!off) {
			pr_warn("string '%s' [offset %u] is not mapped to base BTF",
				btf__str_by_offset(r->btf, off), *str_off);
			return -ENOENT;
		}
		*str_off = off;
	}
	return 0;
}

/* If successful, output of relocation is updated BTF with base BTF pointing
 * at base_btf, and type ids, strings adjusted accordingly.
 */
int btf_relocate(struct btf *btf, const struct btf *base_btf, __u32 **id_map)
{
	unsigned int nr_types = btf__type_cnt(btf);
	const struct btf_header *dist_base_hdr;
	const struct btf_header *base_hdr;
	struct btf_relocate r = {};
	struct btf_type *t;
	int err = 0;
	__u32 id, i;

	r.dist_base_btf = btf__base_btf(btf);
	if (!base_btf || r.dist_base_btf == base_btf)
		return -EINVAL;

	r.nr_dist_base_types = btf__type_cnt(r.dist_base_btf);
	r.nr_base_types = btf__type_cnt(base_btf);
	r.nr_split_types = nr_types - r.nr_dist_base_types;
	r.btf = btf;
	r.base_btf = base_btf;

	r.id_map = calloc(nr_types, sizeof(*r.id_map));
	r.str_map = calloc(btf_header(r.dist_base_btf)->str_len, sizeof(*r.str_map));
	dist_base_hdr = btf_header(r.dist_base_btf);
	base_hdr = btf_header(r.base_btf);
	r.dist_str_len = dist_base_hdr->str_len;
	r.base_str_len = base_hdr->str_len;
	if (!r.id_map || !r.str_map) {
		err = -ENOMEM;
		goto err_out;
	}

	err = btf_relocate_validate_distilled_base(&r);
	if (err)
		goto err_out;

	/* Split BTF ids need to be adjusted as base and distilled base
	 * have different numbers of types, changing the start id of split
	 * BTF.
	 */
	for (id = r.nr_dist_base_types; id < nr_types; id++)
		r.id_map[id] = id + r.nr_base_types - r.nr_dist_base_types;

	/* Build a map from distilled base ids to actual base BTF ids; it is used
	 * to update split BTF id references.  Also build a str_map mapping from
	 * distilled base BTF names to base BTF names.
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
	/* String offsets now need to be updated using the str_map. */
	for (i = 0; i < r.nr_split_types; i++) {
		t = btf_type_by_id(btf, i + r.nr_dist_base_types);
		err = btf_type_visit_str_offs(t, btf_relocate_rewrite_strs, &r);
		if (err)
			goto err_out;
	}
	/* Finally reset base BTF to be base_btf */
	btf_set_base_btf(btf, base_btf);

	if (id_map) {
		*id_map = r.id_map;
		r.id_map = NULL;
	}
err_out:
	free(r.id_map);
	free(r.str_map);
	return err;
}
