// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit test for the connector threads hashtable code.
 *
 * Copyright (c) 2024 Oracle and/or its affiliates.
 * Author: Anjali Kulkarni <anjali.k.kulkarni@oracle.com>
 */
#include <kunit/test.h>

#include "cn_hash_test.h"

#define ARR_SIZE	4
#define HASH_TABLE_LEN	1024

struct add_data {
	pid_t pid;
	int exit_val;
	int key;
};

static struct add_data adata[ARR_SIZE];
static int key_display[HASH_TABLE_LEN];

static int cn_hash_init(struct kunit *test)
{
	for (int i = 0; i < HASH_TABLE_LEN; i++)
		key_display[i] = 0;

	return 0;
}

static void cn_display_htable(struct kunit *test, int len)
{
	int i, err;

	cn_hash_init(test);

	pr_debug("\n");
	pr_debug("Displaying hash table:\n");

	for (i = 0; i < len; i++) {
		err = cn_display_hlist(adata[i].pid, len, &adata[i].key,
					key_display);
		key_display[adata[i].key] = 1;
		KUNIT_EXPECT_EQ(test, err, 0);
	}
}

static void cn_hash_test_add(struct kunit *test)
{
	int err, i;
	int exit_val;

	adata[0].pid = 1;
	adata[0].exit_val = 45;

	adata[1].pid = 2;
	adata[1].exit_val = 13;

	adata[2].pid = 1024;
	adata[2].exit_val = 16;

	adata[3].pid = 1023;
	adata[3].exit_val = 71;

	for (i = 0; i < ARRAY_SIZE(adata); i++) {
		err = cn_add_elem(adata[i].exit_val, adata[i].pid);
		KUNIT_EXPECT_EQ_MSG(test, 0, err,
				"Adding pid %d returned err %d",
				adata[i].pid, err);

		exit_val = cn_get_exval(adata[i].pid);
		KUNIT_EXPECT_EQ(test, adata[i].exit_val, exit_val);
	}

	cn_display_htable(test, ARRAY_SIZE(adata));
}

static void cn_hash_test_del(struct kunit *test)
{
	int i, err;
	int exit_val;

	for (i = 0; i < ARRAY_SIZE(adata); i++) {
		err = cn_del_get_exval(adata[i].pid);
		KUNIT_EXPECT_GT_MSG(test, err, 0,
				"Deleting pid %d returned err %d",
				adata[i].pid, err);

		exit_val = cn_get_exval(adata[i].pid);
		KUNIT_EXPECT_EQ(test, -EINVAL, exit_val);
	}

	cn_display_htable(test, ARRAY_SIZE(adata));
	KUNIT_EXPECT_TRUE(test, cn_table_empty());
}

static void cn_hash_test_del_get_exval(struct kunit *test)
{
	int i, exval;

	for (i = 0; i < ARRAY_SIZE(adata); i++) {
		exval = cn_del_get_exval(adata[i].pid);
		KUNIT_EXPECT_EQ(test, adata[i].exit_val, exval);

		cn_display_htable(test, ARRAY_SIZE(adata));
	}

	KUNIT_EXPECT_TRUE(test, cn_table_empty());
}
static void cn_hash_test_dup_add(struct kunit *test)
{
	int err, exit_val;

	adata[0].pid = 10;
	adata[0].exit_val = 21;

	err = cn_add_elem(adata[0].exit_val, adata[0].pid);
	KUNIT_EXPECT_EQ(test, 0, err);

	exit_val = cn_get_exval(adata[0].pid);
	KUNIT_EXPECT_EQ(test, 21, exit_val);

	adata[1].pid = 10;
	adata[1].exit_val = 12;

	err = cn_add_elem(adata[1].exit_val, adata[1].pid);
	KUNIT_EXPECT_EQ(test, -EEXIST, err);

	exit_val = cn_get_exval(adata[1].pid);
	KUNIT_EXPECT_EQ(test, 21, exit_val);

	cn_display_htable(test, 1);
}

static void cn_hash_test_dup_del(struct kunit *test)
{
	int err;

	err = cn_del_get_exval(adata[0].pid);
	KUNIT_EXPECT_EQ(test, adata[0].exit_val, err);

	err = cn_del_get_exval(adata[0].pid);
	KUNIT_EXPECT_EQ(test, -EINVAL, err);

	KUNIT_EXPECT_TRUE(test, cn_table_empty());
}

static struct kunit_case cn_hashtable_test_cases[] = {
	KUNIT_CASE(cn_hash_test_add),
	KUNIT_CASE(cn_hash_test_del),
	KUNIT_CASE(cn_hash_test_dup_add),
	KUNIT_CASE(cn_hash_test_dup_del),
	KUNIT_CASE(cn_hash_test_add),
	KUNIT_CASE(cn_hash_test_del_get_exval),
	{},
};

static struct kunit_suite cn_hashtable_test_module = {
	.name = "cn_hashtable",
	.init = cn_hash_init,
	.test_cases = cn_hashtable_test_cases,
};
kunit_test_suite(cn_hashtable_test_module);

MODULE_DESCRIPTION("KUnit test for the connector threads hashtable code");
MODULE_LICENSE("GPL");
