// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Facebook */
/* Copyright (c) 2024, Oracle and/or its affiliates. */

#ifdef __KERNEL__
#include <linux/bpf.h>
#include <linux/btf.h>

#define btf_var_secinfos	btf_type_var_secinfo

#else
#include "btf.h"
#include "libbpf_internal.h"
#endif

int btf_type_visit_type_ids(struct btf_type *t, type_id_visit_fn visit, void *ctx)
{
	int i, n, err;

	switch (btf_kind(t)) {
	case BTF_KIND_INT:
	case BTF_KIND_FLOAT:
	case BTF_KIND_ENUM:
	case BTF_KIND_ENUM64:
		return 0;

	case BTF_KIND_FWD:
	case BTF_KIND_CONST:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_PTR:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_FUNC:
	case BTF_KIND_VAR:
	case BTF_KIND_DECL_TAG:
	case BTF_KIND_TYPE_TAG:
		return visit(&t->type, ctx);

	case BTF_KIND_ARRAY: {
		struct btf_array *a = btf_array(t);

		err = visit(&a->type, ctx);
		err = err ?: visit(&a->index_type, ctx);
		return err;
	}

	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION: {
		struct btf_member *m = btf_members(t);

		for (i = 0, n = btf_vlen(t); i < n; i++, m++) {
			err = visit(&m->type, ctx);
			if (err)
				return err;
		}
		return 0;
	}
	case BTF_KIND_FUNC_PROTO: {
		struct btf_param *m = btf_params(t);

		err = visit(&t->type, ctx);
		if (err)
			return err;
		for (i = 0, n = btf_vlen(t); i < n; i++, m++) {
			err = visit(&m->type, ctx);
			if (err)
				return err;
		}
		return 0;
	}

	case BTF_KIND_DATASEC: {
		struct btf_var_secinfo *m = btf_var_secinfos(t);

		for (i = 0, n = btf_vlen(t); i < n; i++, m++) {
			err = visit(&m->type, ctx);
			if (err)
				return err;
		}
		return 0;
	}

	default:
		return -EINVAL;
	}
}

int btf_type_visit_str_offs(struct btf_type *t, str_off_visit_fn visit, void *ctx)
{
	int i, n, err;

	err = visit(&t->name_off, ctx);
	if (err)
		return err;

	switch (btf_kind(t)) {
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION: {
		struct btf_member *m = btf_members(t);

		for (i = 0, n = btf_vlen(t); i < n; i++, m++) {
			err = visit(&m->name_off, ctx);
			if (err)
				return err;
		}
		break;
	}
	case BTF_KIND_ENUM: {
		struct btf_enum *m = btf_enum(t);

		for (i = 0, n = btf_vlen(t); i < n; i++, m++) {
			err = visit(&m->name_off, ctx);
			if (err)
				return err;
		}
		break;
	}
	case BTF_KIND_ENUM64: {
		struct btf_enum64 *m = btf_enum64(t);

		for (i = 0, n = btf_vlen(t); i < n; i++, m++) {
			err = visit(&m->name_off, ctx);
			if (err)
				return err;
		}
		break;
	}
	case BTF_KIND_FUNC_PROTO: {
		struct btf_param *m = btf_params(t);

		for (i = 0, n = btf_vlen(t); i < n; i++, m++) {
			err = visit(&m->name_off, ctx);
			if (err)
				return err;
		}
		break;
	}
	default:
		break;
	}

	return 0;
}
