// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024, Oracle and/or its affiliates. */

#include <test_progs.h>
#include <bpf/btf.h>
#include "btf_helpers.h"

/* Fabricate base, split BTF with references to base types needed; then create
 * split BTF with distilled base BTF and ensure expectations are met:
 *  - only referenced base types from split BTF are present
 *  - struct/union/enum are represented as FWDs unless anonymous, when they
 *    are represented in full, or if embedded in a split BTF struct, in which
 *    case they are represented by a STRUCT with specified size and vlen=0.
 */
static void test_distilled_base(void)
{
	struct btf *btf1 = NULL, *btf2 = NULL, *btf3 = NULL, *btf4 = NULL;

	btf1 = btf__new_empty();
	if (!ASSERT_OK_PTR(btf1, "empty_main_btf"))
		return;

	btf__add_int(btf1, "int", 4, BTF_INT_SIGNED);	/* [1] int */
	btf__add_ptr(btf1, 1);				/* [2] ptr to int */
	btf__add_struct(btf1, "s1", 8);			/* [3] struct s1 { */
	btf__add_field(btf1, "f1", 2, 0, 0);		/*      int *f1; */
							/* } */
	btf__add_struct(btf1, "", 12);			/* [4] struct { */
	btf__add_field(btf1, "f1", 1, 0, 0);		/*	int f1; */
	btf__add_field(btf1, "f2", 3, 32, 0);		/*	struct s1 f2; */
							/* } */
	btf__add_int(btf1, "unsigned int", 4, 0);	/* [5] unsigned int */
	btf__add_union(btf1, "u1", 12);			/* [6] union u1 { */
	btf__add_field(btf1, "f1", 1, 0, 0);		/*	int f1; */
	btf__add_field(btf1, "f2", 2, 0, 0);		/*	int *f2; */
							/* } */
	btf__add_union(btf1, "", 4);			/* [7] union { */
	btf__add_field(btf1, "f1", 1, 0, 0);		/*	int f1; */
							/* } */
	btf__add_enum(btf1, "e1", 4);			/* [8] enum e1 { */
	btf__add_enum_value(btf1, "v1", 1);		/*	v1 = 1; */
							/* } */
	btf__add_enum(btf1, "", 4);			/* [9] enum { */
	btf__add_enum_value(btf1, "av1", 2);		/*	av1 = 2; */
							/* } */
	btf__add_enum64(btf1, "e641", 8, true);		/* [10] enum64 { */
	btf__add_enum64_value(btf1, "v1", 1024);	/*	v1 = 1024; */
							/* } */
	btf__add_enum64(btf1, "", 8, true);		/* [11] enum64 { */
	btf__add_enum64_value(btf1, "v1", 1025);	/*	v1 = 1025; */
							/* } */
	btf__add_struct(btf1, "unneeded", 4);		/* [12] struct unneeded { */
	btf__add_field(btf1, "f1", 1, 0, 0);		/*	int f1; */
							/* } */
	btf__add_struct(btf1, "embedded", 4);		/* [13] struct embedded { */
	btf__add_field(btf1, "f1", 1, 0, 0);		/*	int f1; */
							/* } */
	btf__add_func_proto(btf1, 1);			/* [14] int (*)(int *p1); */
	btf__add_func_param(btf1, "p1", 1);

	btf__add_array(btf1, 1, 1, 3);			/* [15] int [3]; */

	VALIDATE_RAW_BTF(
		btf1,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] PTR '(anon)' type_id=1",
		"[3] STRUCT 's1' size=8 vlen=1\n"
		"\t'f1' type_id=2 bits_offset=0",
		"[4] STRUCT '(anon)' size=12 vlen=2\n"
		"\t'f1' type_id=1 bits_offset=0\n"
		"\t'f2' type_id=3 bits_offset=32",
		"[5] INT 'unsigned int' size=4 bits_offset=0 nr_bits=32 encoding=(none)",
		"[6] UNION 'u1' size=12 vlen=2\n"
		"\t'f1' type_id=1 bits_offset=0\n"
		"\t'f2' type_id=2 bits_offset=0",
		"[7] UNION '(anon)' size=4 vlen=1\n"
		"\t'f1' type_id=1 bits_offset=0",
		"[8] ENUM 'e1' encoding=UNSIGNED size=4 vlen=1\n"
		"\t'v1' val=1",
		"[9] ENUM '(anon)' encoding=UNSIGNED size=4 vlen=1\n"
		"\t'av1' val=2",
		"[10] ENUM64 'e641' encoding=SIGNED size=8 vlen=1\n"
		"\t'v1' val=1024",
		"[11] ENUM64 '(anon)' encoding=SIGNED size=8 vlen=1\n"
		"\t'v1' val=1025",
		"[12] STRUCT 'unneeded' size=4 vlen=1\n"
		"\t'f1' type_id=1 bits_offset=0",
		"[13] STRUCT 'embedded' size=4 vlen=1\n"
		"\t'f1' type_id=1 bits_offset=0",
		"[14] FUNC_PROTO '(anon)' ret_type_id=1 vlen=1\n"
		"\t'p1' type_id=1",
		"[15] ARRAY '(anon)' type_id=1 index_type_id=1 nr_elems=3");

	btf2 = btf__new_empty_split(btf1);
	if (!ASSERT_OK_PTR(btf2, "empty_split_btf"))
		goto cleanup;

	btf__add_ptr(btf2, 3);				/* [16] ptr to struct s1 */
	/* add ptr to struct anon */
	btf__add_ptr(btf2, 4);				/* [17] ptr to struct (anon) */
	btf__add_const(btf2, 6);			/* [18] const union u1 */
	btf__add_restrict(btf2, 7);			/* [19] restrict union (anon) */
	btf__add_volatile(btf2, 8);			/* [20] volatile enum e1 */
	btf__add_typedef(btf2, "et", 9);		/* [21] typedef enum (anon) */
	btf__add_const(btf2, 10);			/* [22] const enum64 e641 */
	btf__add_ptr(btf2, 11);				/* [23] restrict enum64 (anon) */
	btf__add_struct(btf2, "with_embedded", 4);	/* [24] struct with_embedded { */
	btf__add_field(btf2, "f1", 13, 0, 0);		/*	struct embedded f1; */
							/* } */
	btf__add_func(btf2, "fn", BTF_FUNC_STATIC, 14);	/* [25] int fn(int p1); */
	btf__add_typedef(btf2, "arraytype", 15);	/* [26] typedef int[3] foo; */

	VALIDATE_RAW_BTF(
		btf2,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] PTR '(anon)' type_id=1",
		"[3] STRUCT 's1' size=8 vlen=1\n"
		"\t'f1' type_id=2 bits_offset=0",
		"[4] STRUCT '(anon)' size=12 vlen=2\n"
		"\t'f1' type_id=1 bits_offset=0\n"
		"\t'f2' type_id=3 bits_offset=32",
		"[5] INT 'unsigned int' size=4 bits_offset=0 nr_bits=32 encoding=(none)",
		"[6] UNION 'u1' size=12 vlen=2\n"
		"\t'f1' type_id=1 bits_offset=0\n"
		"\t'f2' type_id=2 bits_offset=0",
		"[7] UNION '(anon)' size=4 vlen=1\n"
		"\t'f1' type_id=1 bits_offset=0",
		"[8] ENUM 'e1' encoding=UNSIGNED size=4 vlen=1\n"
		"\t'v1' val=1",
		"[9] ENUM '(anon)' encoding=UNSIGNED size=4 vlen=1\n"
		"\t'av1' val=2",
		"[10] ENUM64 'e641' encoding=SIGNED size=8 vlen=1\n"
		"\t'v1' val=1024",
		"[11] ENUM64 '(anon)' encoding=SIGNED size=8 vlen=1\n"
		"\t'v1' val=1025",
		"[12] STRUCT 'unneeded' size=4 vlen=1\n"
		"\t'f1' type_id=1 bits_offset=0",
		"[13] STRUCT 'embedded' size=4 vlen=1\n"
		"\t'f1' type_id=1 bits_offset=0",
		"[14] FUNC_PROTO '(anon)' ret_type_id=1 vlen=1\n"
		"\t'p1' type_id=1",
		"[15] ARRAY '(anon)' type_id=1 index_type_id=1 nr_elems=3",
		"[16] PTR '(anon)' type_id=3",
		"[17] PTR '(anon)' type_id=4",
		"[18] CONST '(anon)' type_id=6",
		"[19] RESTRICT '(anon)' type_id=7",
		"[20] VOLATILE '(anon)' type_id=8",
		"[21] TYPEDEF 'et' type_id=9",
		"[22] CONST '(anon)' type_id=10",
		"[23] PTR '(anon)' type_id=11",
		"[24] STRUCT 'with_embedded' size=4 vlen=1\n"
		"\t'f1' type_id=13 bits_offset=0",
		"[25] FUNC 'fn' type_id=14 linkage=static",
		"[26] TYPEDEF 'arraytype' type_id=15");

	if (!ASSERT_EQ(0, btf__distill_base(btf2, &btf3, &btf4),
		       "distilled_base") ||
	    !ASSERT_OK_PTR(btf3, "distilled_base") ||
	    !ASSERT_OK_PTR(btf4, "distilled_split"))
		goto cleanup;

	VALIDATE_RAW_BTF(
		btf4,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] FWD 's1' fwd_kind=struct",
		"[3] STRUCT '(anon)' size=12 vlen=2\n"
		"\t'f1' type_id=1 bits_offset=0\n"
		"\t'f2' type_id=2 bits_offset=32",
		"[4] FWD 'u1' fwd_kind=union",
		"[5] UNION '(anon)' size=4 vlen=1\n"
		"\t'f1' type_id=1 bits_offset=0",
		"[6] ENUM 'e1' encoding=UNSIGNED size=4 vlen=0",
		"[7] ENUM '(anon)' encoding=UNSIGNED size=4 vlen=1\n"
		"\t'av1' val=2",
		"[8] ENUM64 'e641' encoding=SIGNED size=8 vlen=0",
		"[9] ENUM64 '(anon)' encoding=SIGNED size=8 vlen=1\n"
		"\t'v1' val=1025",
		"[10] STRUCT 'embedded' size=4 vlen=0",
		"[11] FUNC_PROTO '(anon)' ret_type_id=1 vlen=1\n"
		"\t'p1' type_id=1",
		"[12] ARRAY '(anon)' type_id=1 index_type_id=1 nr_elems=3",
		"[13] PTR '(anon)' type_id=2",
		"[14] PTR '(anon)' type_id=3",
		"[15] CONST '(anon)' type_id=4",
		"[16] RESTRICT '(anon)' type_id=5",
		"[17] VOLATILE '(anon)' type_id=6",
		"[18] TYPEDEF 'et' type_id=7",
		"[19] CONST '(anon)' type_id=8",
		"[20] PTR '(anon)' type_id=9",
		"[21] STRUCT 'with_embedded' size=4 vlen=1\n"
		"\t'f1' type_id=10 bits_offset=0",
		"[22] FUNC 'fn' type_id=11 linkage=static",
		"[23] TYPEDEF 'arraytype' type_id=12");

cleanup:
	btf__free(btf4);
	btf__free(btf3);
	btf__free(btf2);
	btf__free(btf1);
}

/* create split reference BTF from vmlinux + split BTF with a few type references;
 * ensure the resultant split reference BTF is as expected, containing only types
 * needed to disambiguate references from split BTF.
 */
static void test_distilled_base_vmlinux(void)
{
	struct btf *split_btf = NULL, *vmlinux_btf = btf__load_vmlinux_btf();
	struct btf *split_dist = NULL, *base_dist = NULL;
	__s32 int_id, sk_buff_id;

	if (!ASSERT_OK_PTR(vmlinux_btf, "load_vmlinux"))
		return;
	int_id = btf__find_by_name_kind(vmlinux_btf, "int", BTF_KIND_INT);
	if (!ASSERT_GT(int_id, 0, "find_int"))
		goto cleanup;
	sk_buff_id = btf__find_by_name_kind(vmlinux_btf, "sk_buff", BTF_KIND_STRUCT);
	if (!ASSERT_GT(sk_buff_id, 0, "find_sk_buff_id"))
		goto cleanup;
	split_btf = btf__new_empty_split(vmlinux_btf);
	if (!ASSERT_OK_PTR(split_btf, "new_split"))
		goto cleanup;
	btf__add_typedef(split_btf, "myint", int_id);
	btf__add_ptr(split_btf, sk_buff_id);

	if (!ASSERT_EQ(btf__distill_base(split_btf, &base_dist, &split_dist), 0,
		       "distill_vmlinux_base"))
		goto cleanup;

	if (!ASSERT_OK_PTR(split_dist, "split_distilled") ||
	    !ASSERT_OK_PTR(base_dist, "base_dist"))
		goto cleanup;
	VALIDATE_RAW_BTF(
		split_dist,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] FWD 'sk_buff' fwd_kind=struct",
		"[3] TYPEDEF 'myint' type_id=1",
		"[4] PTR '(anon)' type_id=2");

cleanup:
	btf__free(split_dist);
	btf__free(base_dist);
	btf__free(split_btf);
	btf__free(vmlinux_btf);
}

void test_btf_distill(void)
{
	if (test__start_subtest("distilled_base"))
		test_distilled_base();
	if (test__start_subtest("distilled_base_vmlinux"))
		test_distilled_base_vmlinux();
}
