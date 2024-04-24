// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024, Oracle and/or its affiliates. */

#ifdef __KERNEL__
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/string.h>
#include <linux/bpf_verifier.h>

#define btf__type_by_id		btf_type_by_id
#define btf__type_cnt		btf_nr_types
#define btf__base_btf		btf_base_btf
#define btf__name_by_offset	btf_name_by_offset
#define btf_kflag		btf_type_kflag

#define calloc(nmemb, size)	kvcalloc(nmemb, size, GFP_KERNEL | __GFP_NOWARN)
#define free(ptr)		kvfree(ptr)

static inline __u8 btf_int_bits(const struct btf_type *t)
{
	return BTF_INT_BITS(*(__u32 *)(t + 1));
}

static inline struct btf_decl_tag *btf_decl_tag(const struct btf_type *t)
{
	return (struct btf_decl_tag *)(t + 1);
}

#else

#include "btf.h"
#include "bpf.h"
#include "libbpf.h"
#include "libbpf_internal.h"

#endif /* __KERNEL__ */

struct btf;

#define BTF_MAX_NR_TYPES 0x7fffffffU
#define BTF_UNPROCESSED_ID ((__u32)-1)

struct btf_relocate {
	struct btf *btf;
	const struct btf *base_btf;
	const struct btf *dist_base_btf;
	unsigned int nr_base_types;
	__u32 *map;
	__u32 *stack;
	unsigned int stack_size;
	unsigned int stack_limit;
};

/* Find next type after *id in base BTF that matches kind of type t passed in
 * and name (if it is specified).  Match fwd kinds to appropriate kind also.
 */
static int btf_relocate_find_next(struct btf_relocate *r, const struct btf_type *t,
				   __u32 *id, const struct btf_type **tp)
{
	const struct btf_type *nt;
	int kind, tkind = btf_kind(t);
	int tkflag = btf_kflag(t);
	__u32 i;

	for (i = *id + 1; i < r->nr_base_types; i++) {
		nt = btf__type_by_id(r->base_btf, i);
		kind = btf_kind(nt);
		/* enum[64] can match either enum or enum64;
		 * a fwd can match a struct/union of the appropriate
		 * type; otherwise kinds must match.
		 */
		switch (tkind) {
		case BTF_KIND_ENUM:
		case BTF_KIND_ENUM64:
			switch (kind) {
			case BTF_KIND_ENUM64:
			case BTF_KIND_ENUM:
				break;
			default:
				continue;
			}
			break;
		case BTF_KIND_FWD:
			switch (kind) {
			case BTF_KIND_FWD:
				continue;
			case BTF_KIND_STRUCT:
				if (tkflag)
					continue;
				break;
			case BTF_KIND_UNION:
				if (!tkflag)
					continue;
				break;
			default:
				break;
			}
			break;
		default:
			if (kind != tkind)
				continue;
			break;
		}
		/* either names must match or both be anon. */
		if (t->name_off && nt->name_off) {
			if (strcmp(btf__name_by_offset(r->btf, t->name_off),
				   btf__name_by_offset(r->base_btf, nt->name_off)))
				continue;
		} else if (t->name_off != nt->name_off) {
			continue;
		}
		*tp = nt;
		*id = i;
		return 0;
	}
	return -ENOENT;
}

static int btf_relocate_int(struct btf_relocate *r, const char *name,
			     const struct btf_type *t, const struct btf_type *bt)
{
	__u8 encoding, bencoding, bits, bbits;

	if (t->size != bt->size) {
		pr_warn("INT types '%s' disagree on size; distilled base BTF says %d; base BTF says %d\n",
			name, t->size, bt->size);
		return -EINVAL;
	}
	encoding = btf_int_encoding(t);
	bencoding = btf_int_encoding(bt);
	if (encoding != bencoding) {
		pr_warn("INT types '%s' disagree on encoding; distilled base BTF says '(%s/%s/%s); base BTF says '(%s/%s/%s)'\n",
			name,
			encoding & BTF_INT_SIGNED ? "signed" : "unsigned",
			encoding & BTF_INT_CHAR ? "char" : "nonchar",
			encoding & BTF_INT_BOOL ? "bool" : "nonbool",
			bencoding & BTF_INT_SIGNED ? "signed" : "unsigned",
			bencoding & BTF_INT_CHAR ? "char" : "nonchar",
			bencoding & BTF_INT_BOOL ? "bool" : "nonbool");
		return -EINVAL;
	}
	bits = btf_int_bits(t);
	bbits = btf_int_bits(bt);
	if (bits != bbits) {
		pr_warn("INT types '%s' disagree on bit size; distilled base BTF says %d; base BTF says %d\n",
			name, bits, bbits);
		return -EINVAL;
	}
	return 0;
}

static int btf_relocate_float(struct btf_relocate *r, const char *name,
			       const struct btf_type *t, const struct btf_type *bt)
{

	if (t->size != bt->size) {
		pr_warn("float types '%s' disagree on size; distilled base BTF says %d; base BTF says %d\n",
			name, t->size, bt->size);
		return -EINVAL;
	}
	return 0;
}

/* ensure each enum[64] value in type t has equivalent in base BTF and that
 * values match; we must support matching enum64 to enum and vice versa
 * as well as enum to enum and enum64 to enum64.
 */
static int btf_relocate_enum(struct btf_relocate *r, const char *name,
			      const struct btf_type *t, const struct btf_type *bt)
{
	struct btf_enum *v = btf_enum(t);
	struct btf_enum *bv = btf_enum(bt);
	struct btf_enum64 *v64 = btf_enum64(t);
	struct btf_enum64 *bv64 = btf_enum64(bt);
	bool found, match, bisenum, isenum;
	const char *vname, *bvname;
	__u32 name_off, bname_off;
	__u64 val = 0, bval = 0;
	int i, j;

	isenum = btf_kind(t) == BTF_KIND_ENUM;
	for (i = 0; i < btf_vlen(t); i++, v++, v64++) {
		found = match = false;

		if (isenum) {
			name_off = v->name_off;
			val = v->val;
		} else {
			name_off = v64->name_off;
			val = btf_enum64_value(v64);
		}
		if (!name_off)
			continue;
		vname = btf__name_by_offset(r->dist_base_btf, name_off);

		bisenum = btf_kind(bt) == BTF_KIND_ENUM;
		for (j = 0; j < btf_vlen(bt); j++, bv++, bv64++) {
			if (bisenum) {
				bname_off = bv->name_off;
				bval = bv->val;
			} else {
				bname_off = bv64->name_off;
				bval = btf_enum64_value(bv64);
			}
			if (!bname_off)
				continue;
			bvname = btf__name_by_offset(r->base_btf, bname_off);
			if (strcmp(vname, bvname) != 0)
				continue;
			found = true;
			match = val == bval;
			break;
		}
		if (!found) {
			if (t->name_off)
				pr_warn("ENUM[64] types '%s' disagree; distilled base BTF has enum[64] value '%s' (%lld), base BTF does not have that value.\n",
					name, vname, val);
			return -EINVAL;
		}
		if (!match) {
			if (t->name_off)
				pr_warn("ENUM[64] types '%s' disagree on enum value '%s'; distilled base BTF specifies value %lld; base BTF specifies value %lld\n",
					name, vname, val, bval);
			return -EINVAL;
		}
	}
	return 0;
}

/* relocate base types (int, float, enum, enum64 and fwd) */
static int btf_relocate_base_type(struct btf_relocate *r, __u32 id)
{
	const struct btf_type *t = btf_type_by_id(r->dist_base_btf, id);
	const char *name = btf__name_by_offset(r->dist_base_btf, t->name_off);
	const struct btf_type *bt = NULL;
	__u32 base_id = 0;
	int err = 0;

	switch (btf_kind(t)) {
	case BTF_KIND_INT:
	case BTF_KIND_ENUM:
	case BTF_KIND_FLOAT:
	case BTF_KIND_ENUM64:
	case BTF_KIND_FWD:
		break;
	default:
		return 0;
	}

	if (r->map[id] <= BTF_MAX_NR_TYPES)
		return 0;

	while ((err = btf_relocate_find_next(r, t, &base_id, &bt)) != -ENOENT) {
		bt = btf_type_by_id(r->base_btf, base_id);
		switch (btf_kind(t)) {
		case BTF_KIND_INT:
			err = btf_relocate_int(r, name, t, bt);
			break;
		case BTF_KIND_ENUM:
		case BTF_KIND_ENUM64:
			err = btf_relocate_enum(r, name, t, bt);
			break;
		case BTF_KIND_FLOAT:
			err = btf_relocate_float(r, name, t, bt);
			break;
		case BTF_KIND_FWD:
			err = 0;
			break;
		default:
			return 0;
		}
		if (!err) {
			r->map[id] = base_id;
			return 0;
		}
	}
	return err;
}

/* all distilled base BTF members must be in base BTF equivalent. */
static int btf_relocate_check_member(struct btf_relocate *r, const char *name,
				      struct btf_member *m, const struct btf_type *bt,
				      bool verbose)
{
	struct btf_member *bm = (struct btf_member *)(bt + 1);
	const char *kindstr = btf_kind(bt) == BTF_KIND_STRUCT ? "STRUCT" : "UNION";
	const char *mname, *bmname;
	int i, bvlen = btf_vlen(bt);

	mname = btf__name_by_offset(r->dist_base_btf, m->name_off);
	for (i = 0; i < bvlen; i++, bm++) {
		bmname = btf__name_by_offset(r->base_btf, bm->name_off);

		if (!m->name_off || !bm->name_off) {
			if (m->name_off != bm->name_off)
				continue;
			if (bm->offset != m->offset)
				continue;
		} else {
			if (strcmp(mname, bmname) != 0)
				continue;
			if (bm->offset != m->offset) {
				if (verbose) {
					pr_warn("%s '%s' member '%s' disagrees about offset; %d in distilled base BTF versus %d in base BTF\n",
						kindstr, name, mname, bm->offset, m->offset);
					return -EINVAL;
				}
			}
		}
		return 0;
	}
	if (verbose)
		pr_warn("%s '%s' missing member '%s' found in distilled base BTF\n",
			kindstr, name, mname);
	return -EINVAL;
}

static int btf_relocate_struct_type(struct btf_relocate *r, __u32 id)
{
	const struct btf_type *t = btf_type_by_id(r->dist_base_btf, id);
	const char *name = btf__name_by_offset(r->dist_base_btf, t->name_off);
	const struct btf_type *bt = NULL;
	struct btf_member *m;
	const char *kindstr;
	int i, vlen, err = 0;
	__u32 base_id = 0;

	switch (btf_kind(t)) {
	case BTF_KIND_STRUCT:
		kindstr = "STRUCT";
		break;
	case BTF_KIND_UNION:
		kindstr = "UNION";
		break;
	default:
		return 0;
	}

	if (r->map[id] <= BTF_MAX_NR_TYPES)
		return 0;

	vlen = btf_vlen(t);

	while ((err = btf_relocate_find_next(r, t, &base_id, &bt)) != -ENOENT) {
		/* vlen 0 named types (signalling type is embedded in
		 * a split BTF struct/union) must match size exactly
		 */
		if (t->name_off && vlen == 0) {
			if (bt->size != t->size) {
				pr_warn("%s '%s' disagrees about size; is size (%d) in distilled base BTF; in base BTF it is size (%d)\n",
					kindstr, name, t->size, bt->size);
				return -EINVAL;
			}
		}
		/* otherwise must be at least as big */
		if (bt->size < t->size) {
			if (t->name_off) {
				pr_warn("%s '%s' disagrees about size with distilled base BTF (%d); base BTF is smaller (%d)\n",
					kindstr, name, t->size, bt->size);
				return -EINVAL;
			}
			continue;
		}
		/* must have at least as many elements */
		if (btf_vlen(bt) < vlen) {
			if (t->name_off) {
				pr_warn("%s '%s' disagrees about number of members with distilled base BTF (%d); base BTF has less (%d)\n",
					kindstr, name, vlen, btf_vlen(bt));
				return -EINVAL;
			}
			continue;
		}
		m = (struct btf_member *)(t + 1);
		for (i = 0; i < vlen; i++, m++) {
			if (btf_relocate_check_member(r, name, m, bt, t->name_off != 0)) {
				if (t->name_off)
					return -EINVAL;
				err = -EINVAL;
				break;
			}
		}
		if (!err) {
			r->map[id] = base_id;
			return 0;
		}
	}
	return err;
}

/* Use a stack rather than recursion to manage dependent reference types.
 * When a reference type with dependents is encountered, the approach we
 * take depends on whether the dependents have been resolved to base
 * BTF references via the map[].  If they all have, we can simply search
 * for the base BTF type that has those references.  If the references
 * are not resolved, we need to push the type and its dependents onto
 * the stack for later resolution.  We first pop the dependents, and
 * once these have been resolved we pop the reference type with dependents
 * now resolved.
 */
static int btf_relocate_push(struct btf_relocate *r, __u32 id)
{
	if (r->stack_size >= r->stack_limit)
		return -ENOSPC;
	r->stack[r->stack_size++] = id;
	return 0;
}

static __u32 btf_relocate_pop(struct btf_relocate *r)
{
	if (r->stack_size > 0)
		return r->stack[--r->stack_size];
	return BTF_UNPROCESSED_ID;
}

static int btf_relocate_ref_type(struct btf_relocate *r, __u32 id)
{
	const struct btf_type *t;
	const struct btf_type *bt;
	__u32 base_id;
	int err = 0;

	do {
		if (r->map[id] <= BTF_MAX_NR_TYPES)
			continue;
		t = btf_type_by_id(r->dist_base_btf, id);
		switch (btf_kind(t)) {
		case BTF_KIND_CONST:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_PTR:
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_FUNC:
		case BTF_KIND_TYPE_TAG:
		case BTF_KIND_DECL_TAG:
			if (r->map[t->type] <= BTF_MAX_NR_TYPES) {
				bt = NULL;
				base_id = 0;
				while ((err = btf_relocate_find_next(r, t, &base_id, &bt))
				       != -ENOENT) {
					if (btf_kind(t) == BTF_KIND_DECL_TAG) {
						if (btf_decl_tag(t) != btf_decl_tag(bt))
							continue;
					}
					if (bt->type != r->map[t->type])
						continue;
					r->map[id] = base_id;
					break;
				}
				if (err) {
					pr_warn("could not find base BTF type for distilled base BTF type[%u]\n",
						id);
					return err;
				}
			} else {
				if (btf_relocate_push(r, id) < 0 ||
				    btf_relocate_push(r, t->type) < 0)
					return -ENOSPC;
			}
			break;
		case BTF_KIND_ARRAY: {
			struct btf_array *ba, *a = btf_array(t);

			if (r->map[a->type] <= BTF_MAX_NR_TYPES &&
			    r->map[a->index_type] <= BTF_MAX_NR_TYPES) {
				bt = NULL;
				base_id = 0;
				while ((err = btf_relocate_find_next(r, t, &base_id, &bt))
				       != -ENOENT) {
					ba = btf_array(bt);
					if (a->nelems != ba->nelems ||
					    r->map[a->type] != ba->type ||
					    r->map[a->index_type] != ba->index_type)
						continue;
					r->map[id] = base_id;
					break;
				}
				if (err) {
					pr_warn("could not matching find base BTF ARRAY for distilled base BTF ARRAY[%u]\n",
						id);
					return err;
				}
			} else {
				if (btf_relocate_push(r, id) < 0 ||
				    btf_relocate_push(r, a->type) < 0 ||
				    btf_relocate_push(r, a->index_type) < 0)
					return -ENOSPC;
			}
			break;
		}
		case BTF_KIND_FUNC_PROTO: {
			struct btf_param *p = btf_params(t);
			int i, vlen = btf_vlen(t);

			for (i = 0; i < vlen; i++, p++) {
				if (r->map[p->type] > BTF_MAX_NR_TYPES)
					break;
			}
			if (i == vlen && r->map[t->type] <= BTF_MAX_NR_TYPES) {
				bt = NULL;
				base_id = 0;
				while ((err = btf_relocate_find_next(r, t, &base_id, &bt))
				       != -ENOENT) {
					struct btf_param *bp = btf_params(bt);
					int bvlen = btf_vlen(bt);
					int j;

					if (bvlen != vlen)
						continue;
					if (r->map[t->type] != bt->type)
						continue;
					for (j = 0, p = btf_params(t); j < bvlen; j++, bp++, p++) {
						if (r->map[p->type] != bp->type)
							break;
					}
					if (j < bvlen)
						continue;
					r->map[id] = base_id;
					break;
				}
				if (err) {
					pr_warn("could not find matching base BTF FUNC_PROTO for distilled base BTF FUNC_PROTO[%u]\n",
						id);
					return err;
				}
			} else {
				if (btf_relocate_push(r, id) < 0 ||
				    btf_relocate_push(r, t->type) < 0)
					return -ENOSPC;
				for (i = 0, p = btf_params(t); i < btf_vlen(t); i++, p++) {
					if (btf_relocate_push(r, p->type) < 0)
						return -ENOSPC;
				}
			}
			break;
		}
		default:
			return -EINVAL;
		}
	} while ((id = btf_relocate_pop(r)) <= BTF_MAX_NR_TYPES);

	return 0;
}

static int btf_relocate_rewrite_type_id(__u32 *id, void *ctx)
{
	struct btf_relocate *r = ctx;

	*id = r->map[*id];
	return 0;
}

/* If successful, output of relocation is updated BTF with base BTF pointing
 * at base_btf, and type ids, strings adjusted accordingly
 */
int btf_relocate(struct btf *btf, const struct btf *base_btf, __u32 **map_ids)
{
	const struct btf *dist_base_btf = btf__base_btf(btf);
	unsigned int nr_split_types, nr_dist_base_types;
	unsigned int nr_types = btf__type_cnt(btf);
	struct btf_relocate r = {};
	const struct btf_type *t;
	int diff_id, err = 0;
	__u32 id, i;

	if (!base_btf || dist_base_btf == base_btf)
		return 0;

	nr_dist_base_types = btf__type_cnt(dist_base_btf);
	r.nr_base_types = btf__type_cnt(base_btf);
	nr_split_types = nr_types - nr_dist_base_types;
	r.map = calloc(nr_types, sizeof(*r.map));
	r.stack_limit = nr_dist_base_types;
	r.stack = calloc(r.stack_limit, sizeof(*r.stack));
	if (!r.map || !r.stack) {
		err = -ENOMEM;
		goto err_out;
	}
	diff_id = r.nr_base_types - nr_dist_base_types;
	for (id = 1; id < nr_dist_base_types; id++)
		r.map[id] = BTF_UNPROCESSED_ID;
	for (id = nr_dist_base_types; id < nr_types; id++)
		r.map[id] = id + diff_id;

	r.btf = btf;
	r.dist_base_btf = dist_base_btf;
	r.base_btf = base_btf;

	/* Build a map from base references to actual base BTF ids; it is used
	 * to track the state of comparisons.  First map base types and fwds,
	 * next structs/unions, and finally reference types (const, restrict,
	 * ptr, array, func, func_proto etc).
	 */
	for (id = 1; id < nr_dist_base_types; id++) {
		err = btf_relocate_base_type(&r, id);
		if (err)
			goto err_out;
	}
	for (id = 1; id < nr_dist_base_types; id++) {
		err = btf_relocate_struct_type(&r, id);
		if (err)
			goto err_out;
	}
	for (id = 1; id < nr_dist_base_types; id++) {
		err = btf_relocate_ref_type(&r, id);
		if (err)
			goto err_out;
	}
	/* Next, rewrite type ids in split BTF, replacing split ids with updated
	 * ids based on number of types in base BTF, and base ids with
	 * relocated ids from base_btf.
	 */
	for (i = 0, id = nr_dist_base_types; i < nr_split_types; i++, id++) {
		t = btf__type_by_id(btf, id);
		err = btf_type_visit_type_ids((struct btf_type *)t,
					      btf_relocate_rewrite_type_id, &r);
		if (err)
			goto err_out;
	}
	/* Finally reset base BTF to base_btf; as part of this operation, string
	 * offsets are also updated, and we are done.
	 */
	err = btf_set_base_btf(r.btf, (struct btf *)r.base_btf);
err_out:
	if (!err && map_ids)
		*map_ids = r.map;
	else
		free(r.map);
	free(r.stack);
	return err;
}
