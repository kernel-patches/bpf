// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Xiaomi */

#include <test_progs.h>
#include <bpf/btf.h>
#include "btf_helpers.h"

static void permute_base_check(struct btf *btf)
{
	VALIDATE_RAW_BTF(
		btf,
		"[1] STRUCT 's2' size=4 vlen=1\n"
		"\t'm' type_id=4 bits_offset=0",
		"[2] FUNC 'f' type_id=6 linkage=static",
		"[3] PTR '(anon)' type_id=4",
		"[4] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[5] STRUCT 's1' size=4 vlen=1\n"
		"\t'm' type_id=4 bits_offset=0",
		"[6] FUNC_PROTO '(anon)' ret_type_id=4 vlen=1\n"
		"\t'p' type_id=3");
}

/* Ensure btf__permute works as expected in the base-BTF scenario */
static void test_permute_base(void)
{
	struct btf *btf;
	__u32 permute_ids[7];
	int err;

	btf = btf__new_empty();
	if (!ASSERT_OK_PTR(btf, "empty_main_btf"))
		return;

	btf__add_int(btf, "int", 4, BTF_INT_SIGNED);	/* [1] int */
	btf__add_ptr(btf, 1);				/* [2] ptr to int */
	btf__add_struct(btf, "s1", 4);			/* [3] struct s1 { */
	btf__add_field(btf, "m", 1, 0, 0);		/*       int m; */
							/* } */
	btf__add_struct(btf, "s2", 4);			/* [4] struct s2 { */
	btf__add_field(btf, "m", 1, 0, 0);		/*       int m; */
							/* } */
	btf__add_func_proto(btf, 1);			/* [5] int (*)(int *p); */
	btf__add_func_param(btf, "p", 2);
	btf__add_func(btf, "f", BTF_FUNC_STATIC, 5);	/* [6] int f(int *p); */

	VALIDATE_RAW_BTF(
		btf,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] PTR '(anon)' type_id=1",
		"[3] STRUCT 's1' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0",
		"[4] STRUCT 's2' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0",
		"[5] FUNC_PROTO '(anon)' ret_type_id=1 vlen=1\n"
		"\t'p' type_id=2",
		"[6] FUNC 'f' type_id=5 linkage=static");

	permute_ids[0] = 0; /* [0] -> [0] */
	permute_ids[1] = 4; /* [1] -> [4] */
	permute_ids[2] = 3; /* [2] -> [3] */
	permute_ids[3] = 5; /* [3] -> [5] */
	permute_ids[4] = 1; /* [4] -> [1] */
	permute_ids[5] = 6; /* [5] -> [6] */
	permute_ids[6] = 2; /* [6] -> [2] */
	err = btf__permute(btf, permute_ids, ARRAY_SIZE(permute_ids), NULL);
	if (!ASSERT_OK(err, "btf__permute_base"))
		goto done;
	permute_base_check(btf);

	/* ids[0] must be 0 for base BTF */
	permute_ids[0] = 4; /* [0] -> [0] */
	permute_ids[1] = 0; /* [1] -> [4] */
	permute_ids[2] = 3; /* [2] -> [3] */
	permute_ids[3] = 5; /* [3] -> [5] */
	permute_ids[4] = 1; /* [4] -> [1] */
	permute_ids[5] = 6; /* [5] -> [6] */
	permute_ids[6] = 2; /* [6] -> [2] */
	err = btf__permute(btf, permute_ids, ARRAY_SIZE(permute_ids), NULL);
	if (!ASSERT_ERR(err, "btf__permute_base"))
		goto done;
	/* BTF is not modified */
	permute_base_check(btf);

	/* id_map_cnt is invalid */
	permute_ids[0] = 0; /* [0] -> [0] */
	permute_ids[1] = 4; /* [1] -> [4] */
	permute_ids[2] = 3; /* [2] -> [3] */
	permute_ids[3] = 5; /* [3] -> [5] */
	permute_ids[4] = 1; /* [4] -> [1] */
	permute_ids[5] = 6; /* [5] -> [6] */
	permute_ids[6] = 2; /* [6] -> [2] */
	err = btf__permute(btf, permute_ids, ARRAY_SIZE(permute_ids) - 1, NULL);
	if (!ASSERT_ERR(err, "btf__permute_base"))
		goto done;
	/* BTF is not modified */
	permute_base_check(btf);

	/* Multiple types can not be mapped to the same ID */
	permute_ids[0] = 0;
	permute_ids[1] = 4;
	permute_ids[2] = 4;
	permute_ids[3] = 5;
	permute_ids[4] = 1;
	permute_ids[5] = 6;
	permute_ids[6] = 2;
	err = btf__permute(btf, permute_ids, ARRAY_SIZE(permute_ids), NULL);
	if (!ASSERT_ERR(err, "btf__permute_base"))
		goto done;
	/* BTF is not modified */
	permute_base_check(btf);

	/* Type ID must be valid */
	permute_ids[0] = 0;
	permute_ids[1] = 4;
	permute_ids[2] = 3;
	permute_ids[3] = 5;
	permute_ids[4] = 1;
	permute_ids[5] = 7;
	permute_ids[6] = 2;
	err = btf__permute(btf, permute_ids, ARRAY_SIZE(permute_ids), NULL);
	if (!ASSERT_ERR(err, "btf__permute_base"))
		goto done;
	/* BTF is not modified */
	permute_base_check(btf);

done:
	btf__free(btf);
}

static void permute_split_check(struct btf *btf)
{
	VALIDATE_RAW_BTF(
		btf,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] PTR '(anon)' type_id=1",
		"[3] STRUCT 's2' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0",
		"[4] FUNC 'f' type_id=5 linkage=static",
		"[5] FUNC_PROTO '(anon)' ret_type_id=1 vlen=1\n"
		"\t'p' type_id=2",
		"[6] STRUCT 's1' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0");
}

/* Ensure btf__permute works as expected in the split-BTF scenario */
static void test_permute_split(void)
{
	struct btf *split_btf = NULL, *base_btf = NULL;
	__u32 permute_ids[4];
	int err, start_id;

	base_btf = btf__new_empty();
	if (!ASSERT_OK_PTR(base_btf, "empty_main_btf"))
		return;

	btf__add_int(base_btf, "int", 4, BTF_INT_SIGNED);	/* [1] int */
	btf__add_ptr(base_btf, 1);				/* [2] ptr to int */
	VALIDATE_RAW_BTF(
		base_btf,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] PTR '(anon)' type_id=1");
	split_btf = btf__new_empty_split(base_btf);
	if (!ASSERT_OK_PTR(split_btf, "empty_split_btf"))
		goto cleanup;
	btf__add_struct(split_btf, "s1", 4);			/* [3] struct s1 { */
	btf__add_field(split_btf, "m", 1, 0, 0);		/*   int m; */
								/* } */
	btf__add_struct(split_btf, "s2", 4);			/* [4] struct s2 { */
	btf__add_field(split_btf, "m", 1, 0, 0);		/*   int m; */
								/* } */
	btf__add_func_proto(split_btf, 1);			/* [5] int (*)(int p); */
	btf__add_func_param(split_btf, "p", 2);
	btf__add_func(split_btf, "f", BTF_FUNC_STATIC, 5);	/* [6] int f(int *p); */

	VALIDATE_RAW_BTF(
		split_btf,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] PTR '(anon)' type_id=1",
		"[3] STRUCT 's1' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0",
		"[4] STRUCT 's2' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0",
		"[5] FUNC_PROTO '(anon)' ret_type_id=1 vlen=1\n"
		"\t'p' type_id=2",
		"[6] FUNC 'f' type_id=5 linkage=static");

	start_id = btf__type_cnt(base_btf);
	permute_ids[3 - start_id] = 6; /* [3] -> [6] */
	permute_ids[4 - start_id] = 3; /* [4] -> [3] */
	permute_ids[5 - start_id] = 5; /* [5] -> [5] */
	permute_ids[6 - start_id] = 4; /* [6] -> [4] */
	err = btf__permute(split_btf, permute_ids, ARRAY_SIZE(permute_ids), NULL);
	if (!ASSERT_OK(err, "btf__permute_split"))
		goto cleanup;
	permute_split_check(split_btf);

	/*
	 * For split BTF, id_map_cnt must equal to the number of types
	 * added on top of base BTF
	 */
	permute_ids[3 - start_id] = 4;
	permute_ids[4 - start_id] = 3;
	permute_ids[5 - start_id] = 5;
	permute_ids[6 - start_id] = 6;
	err = btf__permute(split_btf, permute_ids, ARRAY_SIZE(permute_ids) - 1, NULL);
	if (!ASSERT_ERR(err, "btf__permute_split"))
		goto cleanup;
	/* BTF is not modified */
	permute_split_check(split_btf);

	/* Multiple types can not be mapped to the same ID */
	permute_ids[3 - start_id] = 4;
	permute_ids[4 - start_id] = 3;
	permute_ids[5 - start_id] = 3;
	permute_ids[6 - start_id] = 6;
	err = btf__permute(split_btf, permute_ids, ARRAY_SIZE(permute_ids), NULL);
	if (!ASSERT_ERR(err, "btf__permute_split"))
		goto cleanup;
	/* BTF is not modified */
	permute_split_check(split_btf);

	/* Can not map to base ID */
	permute_ids[3 - start_id] = 4;
	permute_ids[4 - start_id] = 2;
	permute_ids[5 - start_id] = 5;
	permute_ids[6 - start_id] = 6;
	err = btf__permute(split_btf, permute_ids, ARRAY_SIZE(permute_ids), NULL);
	if (!ASSERT_ERR(err, "btf__permute_split"))
		goto cleanup;
	/* BTF is not modified */
	permute_split_check(split_btf);

cleanup:
	btf__free(split_btf);
	btf__free(base_btf);
}

/* Ensure selected types can be moved into a split BTF while permuting. */
static void test_permute_transfer(void)
{
	struct btf *btf = NULL, *transfer_btf = NULL;
	LIBBPF_OPTS(btf_permute_opts, opts);
	__u32 permute_ids[11];
	int err, id, foo_name_off = -1, shared_name_off, foo_funcs = 0, shared_funcs = 0;

	btf = btf__new_empty();
	if (!ASSERT_OK_PTR(btf, "empty_main_btf"))
		return;

	btf__add_int(btf, "int", 4, BTF_INT_SIGNED); /* [1] int */
	btf__add_func_proto(btf, 1);                  /* [2] int (*)(void) */
	btf__add_func(btf, "foo", BTF_FUNC_STATIC, 2); /* [3] int foo(void) */
	btf__add_loc_param(btf, 4, BTF_LOC_PARAM_SIGNED); /* [4] location */
	btf__add_loc_param_value(btf, 0);
	btf__add_loc_proto(btf);                       /* [5] location proto */
	btf__add_loc_proto_param(btf, 4);
	btf__add_locsec(btf, ".locs");                /* [6] location section */
	btf__add_locsec_loc(btf, 3, 5, 128);
	btf__add_locsec_loc(btf, 3, 5, 0);
	btf__add_int(btf, "long", 8, BTF_INT_SIGNED); /* [7] long */
	btf__add_func(btf, "foo", BTF_FUNC_STATIC, 2);    /* [8] another foo */
	btf__add_func(btf, "shared", BTF_FUNC_STATIC, 2); /* [9] shared string */
	btf__add_struct(btf, "shared", 4);                /* [10] retains string */

	permute_ids[0] = 0;
	permute_ids[1] = 1;
	permute_ids[2] = BTF_PERMUTE_ID_TRANSFER | 2;
	permute_ids[3] = BTF_PERMUTE_ID_TRANSFER | 3;
	permute_ids[4] = BTF_PERMUTE_ID_TRANSFER | 5;
	permute_ids[5] = BTF_PERMUTE_ID_TRANSFER | 6;
	permute_ids[6] = BTF_PERMUTE_ID_TRANSFER | 7;
	permute_ids[7] = 4;
	permute_ids[8] = BTF_PERMUTE_ID_TRANSFER | 8;
	permute_ids[9] = BTF_PERMUTE_ID_TRANSFER | 9;
	permute_ids[10] = 10;
	opts.transfer_btf = &transfer_btf;
	err = btf__permute(btf, permute_ids, ARRAY_SIZE(permute_ids), &opts);
	if (!ASSERT_OK(err, "btf__permute_transfer") ||
	    !ASSERT_OK_PTR(transfer_btf, "transfer_btf"))
		goto cleanup;

	ASSERT_EQ(4, btf__type_cnt(btf), "base_type_cnt");
	ASSERT_EQ(-ENOENT, btf__find_str(btf, "foo"), "func_name_not_in_base");
	shared_name_off = btf__find_str(btf, "shared");
	if (!ASSERT_GE(shared_name_off, 0, "shared_name_in_base"))
		goto cleanup;
	for (id = btf__type_cnt(btf); id < btf__type_cnt(transfer_btf); id++) {
		const struct btf_type *t = btf__type_by_id(transfer_btf, id);

		if (!btf_is_func(t))
			continue;
		if (!strcmp(btf__name_by_offset(transfer_btf, t->name_off), "foo")) {
			foo_funcs++;
			if (foo_name_off < 0)
				foo_name_off = t->name_off;
			else if (!ASSERT_EQ(foo_name_off, t->name_off, "local_foo_dedup"))
				goto cleanup;
		} else if (!strcmp(btf__name_by_offset(transfer_btf, t->name_off), "shared")) {
			shared_funcs++;
			if (!ASSERT_EQ(shared_name_off, t->name_off, "shared_name_reuses_base"))
				goto cleanup;
		}
	}
	if (!ASSERT_GE(foo_name_off, 0, "local_foo_name"))
		goto cleanup;
	if (!ASSERT_EQ(2, foo_funcs, "local_foo_count") ||
	    !ASSERT_EQ(1, shared_funcs, "shared_func_count"))
		goto cleanup;
	VALIDATE_RAW_BTF(
		transfer_btf,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] INT 'long' size=8 bits_offset=0 nr_bits=64 encoding=SIGNED",
		"[3] STRUCT 'shared' size=4 vlen=0",
		"[4] FUNC_PROTO '(anon)' ret_type_id=1 vlen=0",
		"[5] FUNC 'foo' type_id=4 linkage=static",
		"[6] LOC_PARAM '(anon)' size=4 flags=0x1 vlen=1\n"
		"\tvalue=0",
		"[7] LOC_PROTO '(anon)' vlen=1\n"
		"\ttype_id=6",
		"[8] LOCSEC '.locs' vlen=2\n"
		"\tfunc_type_id=5 loc_proto_type_id=7 offset=128\n"
		"\tfunc_type_id=5 loc_proto_type_id=7 offset=0",
		"[9] FUNC 'foo' type_id=4 linkage=static",
		"[10] FUNC 'shared' type_id=4 linkage=static");
cleanup:
	btf__free(transfer_btf);
	btf__free(btf);
}

/* Permuting BTF with a layout section must keep section offsets in sync. */
static void test_permute_layout(void)
{
	LIBBPF_OPTS(btf_new_opts, opts, .add_layout = true);
	LIBBPF_OPTS(btf_permute_opts, permute_opts);
	struct btf *btf, *parsed, *transfer_btf = NULL;
	const void *raw;
	__u32 raw_sz;
	__u32 permute_ids[] = { 0, 1, BTF_PERMUTE_ID_TRANSFER | 2 };
	int err;

	btf = btf__new_empty_opts(&opts);
	if (!ASSERT_OK_PTR(btf, "empty_layout_btf"))
		return;

	btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
	btf__add_ptr(btf, 1);
	permute_opts.transfer_btf = &transfer_btf;
	err = btf__permute(btf, permute_ids, ARRAY_SIZE(permute_ids), &permute_opts);
	if (!ASSERT_OK(err, "btf__permute_layout"))
		goto cleanup;

	raw = btf__raw_data(btf, &raw_sz);
	parsed = btf__new(raw, raw_sz);
	if (!ASSERT_OK_PTR(parsed, "parse_permuted_layout"))
		goto cleanup;
	btf__free(parsed);
cleanup:
	btf__free(transfer_btf);
	btf__free(btf);
}

void test_btf_permute(void)
{
	if (test__start_subtest("permute_base"))
		test_permute_base();
	if (test__start_subtest("permute_split"))
		test_permute_split();
	if (test__start_subtest("permute_transfer"))
		test_permute_transfer();
	if (test__start_subtest("permute_layout"))
		test_permute_layout();
}
