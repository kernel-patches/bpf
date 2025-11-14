// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Xiaomi */

#include <test_progs.h>
#include <bpf/btf.h>
#include "btf_helpers.h"

/* Ensure btf__permute work as expected with base BTF */
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

	permute_ids[0] = 0;
	permute_ids[1] = 4; /* [1] -> [4] */
	permute_ids[2] = 3; /* [2] -> [3] */
	permute_ids[3] = 5; /* [3] -> [5] */
	permute_ids[4] = 1; /* [4] -> [1] */
	permute_ids[5] = 6; /* [5] -> [6] */
	permute_ids[6] = 2; /* [6] -> [2] */
	err = btf__permute(btf, permute_ids, ARRAY_SIZE(permute_ids), NULL);
	if (!ASSERT_OK(err, "btf__permute_base"))
		goto done;

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

	/* For base BTF, id_map[0] must be 0 */
	permute_ids[0] = 4;
	permute_ids[1] = 0;
	permute_ids[2] = 3;
	permute_ids[3] = 5;
	permute_ids[4] = 1;
	permute_ids[5] = 6;
	permute_ids[6] = 2;
	err = btf__permute(btf, permute_ids, ARRAY_SIZE(permute_ids), NULL);
	if (!ASSERT_ERR(err, "btf__permute_base"))
		goto done;

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

	/*
	 * For base BTF, id_map_cnt must equal to the number of types
	 * include VOID type
	 */
	permute_ids[0] = 4;
	permute_ids[1] = 0;
	permute_ids[2] = 3;
	permute_ids[3] = 5;
	permute_ids[4] = 1;
	permute_ids[5] = 6;
	err = btf__permute(btf, permute_ids, ARRAY_SIZE(permute_ids) - 1, NULL);
	if (!ASSERT_ERR(err, "btf__permute_base"))
		goto done;

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

done:
	btf__free(btf);
}

/* Ensure btf__permute work as expected with split BTF */
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

	permute_ids[0] = 6; /* [3] -> [6] */
	permute_ids[1] = 3; /* [4] -> [3] */
	permute_ids[2] = 5; /* [5] -> [5] */
	permute_ids[3] = 4; /* [6] -> [4] */
	err = btf__permute(split_btf, permute_ids, ARRAY_SIZE(permute_ids), NULL);
	if (!ASSERT_OK(err, "btf__permute_split"))
		goto cleanup;

	VALIDATE_RAW_BTF(
		split_btf,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] PTR '(anon)' type_id=1",
		"[3] STRUCT 's2' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0",
		"[4] FUNC 'f' type_id=5 linkage=static",
		"[5] FUNC_PROTO '(anon)' ret_type_id=1 vlen=1\n"
		"\t'p' type_id=2",
		"[6] STRUCT 's1' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0");

	/*
	 * For split BTF, id_map_cnt must equal to the number of types
	 * added on top of base BTF
	 */
	permute_ids[0] = 4;
	permute_ids[1] = 3;
	permute_ids[2] = 5;
	permute_ids[3] = 6;
	err = btf__permute(split_btf, permute_ids, 3, NULL);
	if (!ASSERT_ERR(err, "btf__permute_split"))
		goto cleanup;

	VALIDATE_RAW_BTF(
		split_btf,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] PTR '(anon)' type_id=1",
		"[3] STRUCT 's2' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0",
		"[4] FUNC 'f' type_id=5 linkage=static",
		"[5] FUNC_PROTO '(anon)' ret_type_id=1 vlen=1\n"
		"\t'p' type_id=2",
		"[6] STRUCT 's1' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0");

	/* Multiple types can not be mapped to the same ID */
	permute_ids[0] = 4;
	permute_ids[1] = 3;
	permute_ids[2] = 3;
	permute_ids[3] = 6;
	err = btf__permute(split_btf, permute_ids, 4, NULL);
	if (!ASSERT_ERR(err, "btf__permute_split"))
		goto cleanup;

	VALIDATE_RAW_BTF(
		split_btf,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] PTR '(anon)' type_id=1",
		"[3] STRUCT 's2' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0",
		"[4] FUNC 'f' type_id=5 linkage=static",
		"[5] FUNC_PROTO '(anon)' ret_type_id=1 vlen=1\n"
		"\t'p' type_id=2",
		"[6] STRUCT 's1' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0");

	/* Can not map to base ID */
	permute_ids[0] = 4;
	permute_ids[1] = 2;
	permute_ids[2] = 5;
	permute_ids[3] = 6;
	err = btf__permute(split_btf, permute_ids, 4, NULL);
	if (!ASSERT_ERR(err, "btf__permute_split"))
		goto cleanup;

	VALIDATE_RAW_BTF(
		split_btf,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] PTR '(anon)' type_id=1",
		"[3] STRUCT 's2' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0",
		"[4] FUNC 'f' type_id=5 linkage=static",
		"[5] FUNC_PROTO '(anon)' ret_type_id=1 vlen=1\n"
		"\t'p' type_id=2",
		"[6] STRUCT 's1' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0");

cleanup:
	btf__free(split_btf);
	btf__free(base_btf);
}

/* Verify btf__permute function drops types correctly with base_btf */
static void test_permute_drop_base(void)
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

	/* Drop ID 4 */
	permute_ids[0] = 0;
	permute_ids[1] = 5; /* [1] -> [5] */
	permute_ids[2] = 1; /* [2] -> [1] */
	permute_ids[3] = 2; /* [3] -> [2] */
	permute_ids[4] = 0; /* Drop [4] */
	permute_ids[5] = 3; /* [5] -> [3] */
	permute_ids[6] = 4; /* [6] -> [4] */
	err = btf__permute(btf, permute_ids, ARRAY_SIZE(permute_ids), NULL);
	if (!ASSERT_OK(err, "btf__permute_drop_base"))
		goto done;

	VALIDATE_RAW_BTF(
		btf,
		"[1] PTR '(anon)' type_id=5",
		"[2] STRUCT 's1' size=4 vlen=1\n"
		"\t'm' type_id=5 bits_offset=0",
		"[3] FUNC_PROTO '(anon)' ret_type_id=5 vlen=1\n"
		"\t'p' type_id=1",
		"[4] FUNC 'f' type_id=3 linkage=static",
		"[5] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED");

	/* Continue dropping */
	permute_ids[0] = 0;
	permute_ids[1] = 1; /* [1] -> [1] */
	permute_ids[2] = 2; /* [2] -> [2] */
	permute_ids[3] = 3; /* [3] -> [3] */
	permute_ids[4] = 0; /* Drop [4] */
	permute_ids[5] = 4; /* [5] -> [4] */
	err = btf__permute(btf, permute_ids, 6, NULL);
	if (!ASSERT_OK(err, "btf__permute_drop_base_fail"))
		goto done;

	VALIDATE_RAW_BTF(
		btf,
		"[1] PTR '(anon)' type_id=4",
		"[2] STRUCT 's1' size=4 vlen=1\n"
		"\t'm' type_id=4 bits_offset=0",
		"[3] FUNC_PROTO '(anon)' ret_type_id=4 vlen=1\n"
		"\t'p' type_id=1",
		"[4] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED");

	/* Cannot drop the ID referenced by others */
	permute_ids[0] = 0;
	permute_ids[1] = 2;
	permute_ids[2] = 3;
	permute_ids[3] = 1;
	permute_ids[4] = 0; /* [4] is referenced by others */
	err = btf__permute(btf, permute_ids, 5, NULL);
	if (!ASSERT_ERR(err, "btf__permute_drop_base_fail"))
		goto done;

	VALIDATE_RAW_BTF(
		btf,
		"[1] PTR '(anon)' type_id=4",
		"[2] STRUCT 's1' size=4 vlen=1\n"
		"\t'm' type_id=4 bits_offset=0",
		"[3] FUNC_PROTO '(anon)' ret_type_id=4 vlen=1\n"
		"\t'p' type_id=1",
		"[4] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED");

	/* Drop 2 IDs at once */
	permute_ids[0] = 0;
	permute_ids[1] = 2; /* [1] -> [2] */
	permute_ids[2] = 0; /* Drop [2] */
	permute_ids[3] = 0; /* Drop [3] */
	permute_ids[4] = 1; /* [4] -> [1] */
	err = btf__permute(btf, permute_ids, 5, NULL);
	if (!ASSERT_OK(err, "btf__permute_drop_base_fail"))
		goto done;

	VALIDATE_RAW_BTF(
		btf,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] PTR '(anon)' type_id=1");

	/* Drop all IDs */
	permute_ids[0] = 0;
	permute_ids[1] = 0; /* Drop [1] */
	permute_ids[2] = 0; /* Drop [2] */
	err = btf__permute(btf, permute_ids, 3, NULL);
	if (!ASSERT_OK(err, "btf__permute_drop_base_fail"))
		goto done;
	if (!ASSERT_EQ(btf__type_cnt(btf), 0, "btf__permute_drop_split all"))
		goto done;

done:
	btf__free(btf);
}

/* Verify btf__permute function drops types correctly with split BTF */
static void test_permute_drop_split(void)
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

	/* Drop ID 4 */
	permute_ids[0] = 5; /* [3] -> [5] */
	permute_ids[1] = 0; /* Drop [4] */
	permute_ids[2] = 3; /* [5] -> [3] */
	permute_ids[3] = 4; /* [6] -> [4] */
	err = btf__permute(split_btf, permute_ids, ARRAY_SIZE(permute_ids), NULL);
	if (!ASSERT_OK(err, "btf__permute_drop_split"))
		goto cleanup;

	VALIDATE_RAW_BTF(
		split_btf,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] PTR '(anon)' type_id=1",
		"[3] FUNC_PROTO '(anon)' ret_type_id=1 vlen=1\n"
		"\t'p' type_id=2",
		"[4] FUNC 'f' type_id=3 linkage=static",
		"[5] STRUCT 's1' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0");

	/* Can not drop the type referenced by others */
	permute_ids[0] = 0; /* [3] is referenced by [4] */
	permute_ids[1] = 4;
	permute_ids[2] = 3;
	err = btf__permute(split_btf, permute_ids, 3, NULL);
	if (!ASSERT_ERR(err, "btf__permute_drop_split"))
		goto cleanup;

	VALIDATE_RAW_BTF(
		split_btf,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] PTR '(anon)' type_id=1",
		"[3] FUNC_PROTO '(anon)' ret_type_id=1 vlen=1\n"
		"\t'p' type_id=2",
		"[4] FUNC 'f' type_id=3 linkage=static",
		"[5] STRUCT 's1' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0");

	/* Continue dropping */
	permute_ids[0] = 0; /* Drop [3] */
	permute_ids[1] = 0; /* Drop [4] */
	permute_ids[2] = 3; /* [5] -> [3] */
	err = btf__permute(split_btf, permute_ids, 3, NULL);
	if (!ASSERT_OK(err, "btf__permute_drop_split"))
		goto cleanup;

	VALIDATE_RAW_BTF(
		split_btf,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] PTR '(anon)' type_id=1",
		"[3] STRUCT 's1' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0");

	/* Continue dropping */
	permute_ids[0] = 0; /* Drop [3] */
	err = btf__permute(split_btf, permute_ids, 1, NULL);
	if (!ASSERT_OK(err, "btf__permute_drop_split"))
		goto cleanup;

	VALIDATE_RAW_BTF(
		split_btf,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] PTR '(anon)' type_id=1");

cleanup:
	btf__free(split_btf);
	btf__free(base_btf);
}

/* Verify btf__permute then btf__dedup work correctly */
static void test_permute_drop_dedup(void)
{
	struct btf *btf, *new_btf;
	const struct btf_header *hdr;
	const void *btf_data;
	char expect_strs[] = "\0int\0s1\0m\0tag1\0tag2\0tag3";
	char expect_strs_dedupped[] = "\0int\0s1\0m\0tag1";
	__u32 permute_ids[6], btf_size;
	int err;

	btf = btf__new_empty();
	if (!ASSERT_OK_PTR(btf, "empty_main_btf"))
		return;

	btf__add_int(btf, "int", 4, BTF_INT_SIGNED);	/* [1] int */
	btf__add_struct(btf, "s1", 4);			/* [2] struct s1 { */
	btf__add_field(btf, "m", 1, 0, 0);		/*       int m; */
							/* } */
	btf__add_decl_tag(btf, "tag1", 2, -1);		/* [3] tag -> s1: tag1 */
	btf__add_decl_tag(btf, "tag2", 2, 1);		/* [4] tag -> s1/m: tag2 */
	btf__add_decl_tag(btf, "tag3", 2, 1);		/* [5] tag -> s1/m: tag3 */

	VALIDATE_RAW_BTF(
		btf,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] STRUCT 's1' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0",
		"[3] DECL_TAG 'tag1' type_id=2 component_idx=-1",
		"[4] DECL_TAG 'tag2' type_id=2 component_idx=1",
		"[5] DECL_TAG 'tag3' type_id=2 component_idx=1");

	btf_data = btf__raw_data(btf, &btf_size);
	hdr = btf_data;
	if (!ASSERT_EQ(hdr->str_len, ARRAY_SIZE(expect_strs), "expect_strs"))
		goto done;

	new_btf = btf__new(btf_data, btf_size);
	if (!ASSERT_OK_PTR(new_btf, "btf__new"))
		goto done;

	/* Drop 2 IDs result in unreferenced strings */
	permute_ids[0] = 0;
	permute_ids[1] = 3; /* [1] -> [3] */
	permute_ids[2] = 1; /* [2] -> [1] */
	permute_ids[3] = 2; /* [3] -> [2] */
	permute_ids[4] = 0; /* Drop result in unreferenced "tag2" */
	permute_ids[5] = 0; /* Drop result in unreferenced "tag3" */
	err = btf__permute(new_btf, permute_ids, ARRAY_SIZE(permute_ids), NULL);
	if (!ASSERT_OK(err, "btf__permute"))
		goto done;

	VALIDATE_RAW_BTF(
		new_btf,
		"[1] STRUCT 's1' size=4 vlen=1\n"
		"\t'm' type_id=3 bits_offset=0",
		"[2] DECL_TAG 'tag1' type_id=1 component_idx=-1",
		"[3] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED");

	btf_data = btf__raw_data(new_btf, &btf_size);
	hdr = btf_data;
	if (!ASSERT_EQ(hdr->str_len, ARRAY_SIZE(expect_strs), "expect_strs"))
		goto done;

	err = btf__dedup(new_btf, NULL);
	if (!ASSERT_OK(err, "btf__dedup"))
		goto done;

	btf_data = btf__raw_data(new_btf, &btf_size);
	hdr = btf_data;
	if (!ASSERT_EQ(hdr->str_len, ARRAY_SIZE(expect_strs_dedupped), "expect_strs_dedupped"))
		goto done;

done:
	btf__free(btf);
	btf__free(new_btf);
}

void test_btf_permute(void)
{
	if (test__start_subtest("permute_base"))
		test_permute_base();
	if (test__start_subtest("permute_split"))
		test_permute_split();
	if (test__start_subtest("permute_drop_base"))
		test_permute_drop_base();
	if (test__start_subtest("permute_drop_split"))
		test_permute_drop_split();
	if (test__start_subtest("permute_drop_dedup"))
		test_permute_drop_dedup();
}
