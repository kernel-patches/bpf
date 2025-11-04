// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Xiaomi */

#include <test_progs.h>
#include <bpf/btf.h>
#include "btf_helpers.h"

/* ensure btf__permute work as expected with base_btf */
static void test_permute_base(void)
{
	struct btf *btf;
	__u32 permute_ids[6];
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

	permute_ids[0] = 4; /* struct s2 */
	permute_ids[1] = 3; /* struct s1 */
	permute_ids[2] = 5; /* int (*)(int *p) */
	permute_ids[3] = 1; /* int */
	permute_ids[4] = 6; /* int f(int *p) */
	permute_ids[5] = 2; /* ptr to int */
	err = btf__permute(btf, permute_ids, NULL);
	if (!ASSERT_OK(err, "btf__permute"))
		goto done;

	VALIDATE_RAW_BTF(
		btf,
		"[1] STRUCT 's2' size=4 vlen=1\n"
		"\t'm' type_id=4 bits_offset=0",
		"[2] STRUCT 's1' size=4 vlen=1\n"
		"\t'm' type_id=4 bits_offset=0",
		"[3] FUNC_PROTO '(anon)' ret_type_id=4 vlen=1\n"
		"\t'p' type_id=6",
		"[4] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[5] FUNC 'f' type_id=3 linkage=static",
		"[6] PTR '(anon)' type_id=4");

done:
	btf__free(btf);
}

/* ensure btf__permute work as expected with split_btf */
static void test_permute_split(void)
{
	struct btf *split_btf = NULL, *base_btf = NULL;
	__u32 permute_ids[4];
	int err;

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

	permute_ids[0] = 6; /* int f(int *p) */
	permute_ids[1] = 3; /* struct s1 */
	permute_ids[2] = 5; /* int (*)(int *p) */
	permute_ids[3] = 4; /* struct s2 */
	err = btf__permute(split_btf, permute_ids, NULL);
	if (!ASSERT_OK(err, "btf__permute"))
		goto cleanup;

	VALIDATE_RAW_BTF(
		split_btf,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] PTR '(anon)' type_id=1",
		"[3] FUNC 'f' type_id=5 linkage=static",
		"[4] STRUCT 's1' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0",
		"[5] FUNC_PROTO '(anon)' ret_type_id=1 vlen=1\n"
		"\t'p' type_id=2",
		"[6] STRUCT 's2' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0");

cleanup:
	btf__free(split_btf);
	btf__free(base_btf);
}

void test_btf_permute(void)
{
	if (test__start_subtest("permute_base"))
		test_permute_base();
	if (test__start_subtest("permute_split"))
		test_permute_split();
}
