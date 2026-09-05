// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <bpf/btf.h>
#include <linux/btf.h>
#include <test_progs.h>

#define SPIN_LOCK 2
#define LIST_HEAD 3
#define LIST_NODE 4
/* Keep in sync with BTF_MAX_OWNERSHIP_DEPTH. */
#define MAX_OWNERSHIP_DEPTH 8

static struct btf *init_btf(void)
{
	struct btf *btf;
	int id;

	btf = btf__new_empty();
	if (!ASSERT_OK_PTR(btf, "btf__new_empty"))
		return NULL;
	id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
	if (!ASSERT_EQ(id, 1, "btf__add_int"))
		goto err_out;
	id = btf__add_struct(btf, "bpf_spin_lock", 4);
	if (!ASSERT_EQ(id, SPIN_LOCK, "btf__add_struct bpf_spin_lock"))
		goto err_out;
	id = btf__add_struct(btf, "bpf_list_head", 16);
	if (!ASSERT_EQ(id, LIST_HEAD, "btf__add_struct bpf_list_head"))
		goto err_out;
	id = btf__add_struct(btf, "bpf_list_node", 24);
	if (!ASSERT_EQ(id, LIST_NODE, "btf__add_struct bpf_list_node"))
		goto err_out;
	return btf;

err_out:
	btf__free(btf);
	return NULL;
}

static int add_local_kptr(struct btf *btf, int pointee_id, const char *tag)
{
	int id;

	id = btf__add_type_tag(btf, tag, pointee_id);
	if (!ASSERT_GT(id, 0, "btf__add_type_tag"))
		return id;
	id = btf__add_ptr(btf, id);
	ASSERT_GT(id, 0, "btf__add_ptr");
	return id;
}

static void test_self_cycle(const char *tag, int expected_err)
{
	struct btf *btf;
	int id, err;

	btf = init_btf();
	if (!ASSERT_OK_PTR(btf, "init_btf"))
		return;
	id = add_local_kptr(btf, 7, tag);
	if (id <= 0)
		goto out;
	id = btf__add_struct(btf, "self_cycle", 8);
	if (!ASSERT_EQ(id, 7, "btf__add_struct self_cycle"))
		goto out;
	err = btf__add_field(btf, "next", 6, 0, 0);
	if (!ASSERT_OK(err, "btf__add_field self_cycle::next"))
		goto out;

	err = btf__load_into_kernel(btf);
	ASSERT_EQ(err, expected_err, "check btf");
out:
	btf__free(btf);
}

static void test_aba_cycle(void)
{
	struct btf *btf;
	int id, err;

	btf = init_btf();
	if (!ASSERT_OK_PTR(btf, "init_btf"))
		return;
	id = add_local_kptr(btf, 10, "kptr");
	if (id <= 0)
		goto out;
	id = add_local_kptr(btf, 9, "kptr");
	if (id <= 0)
		goto out;
	id = btf__add_struct(btf, "cycle_a", 8);
	if (!ASSERT_EQ(id, 9, "btf__add_struct cycle_a"))
		goto out;
	err = btf__add_field(btf, "b", 6, 0, 0);
	if (!ASSERT_OK(err, "btf__add_field cycle_a::b"))
		goto out;
	id = btf__add_struct(btf, "cycle_b", 8);
	if (!ASSERT_EQ(id, 10, "btf__add_struct cycle_b"))
		goto out;
	err = btf__add_field(btf, "a", 8, 0, 0);
	if (!ASSERT_OK(err, "btf__add_field cycle_b::a"))
		goto out;

	err = btf__load_into_kernel(btf);
	ASSERT_EQ(err, -ELOOP, "check btf");
out:
	btf__free(btf);
}

static void test_mixed_cycle(void)
{
	struct btf *btf;
	int id, err;

	btf = init_btf();
	if (!ASSERT_OK_PTR(btf, "init_btf"))
		return;
	id = add_local_kptr(btf, 7, "kptr");
	if (id <= 0)
		goto out;
	id = btf__add_struct(btf, "mixed_owner", 20);
	if (!ASSERT_EQ(id, 7, "btf__add_struct mixed_owner"))
		goto out;
	err = btf__add_field(btf, "root", LIST_HEAD, 0, 0);
	if (!ASSERT_OK(err, "btf__add_field mixed_owner::root"))
		goto out;
	err = btf__add_field(btf, "lock", SPIN_LOCK, 128, 0);
	if (!ASSERT_OK(err, "btf__add_field mixed_owner::lock"))
		goto out;
	id = btf__add_decl_tag(btf, "contains:mixed_node:node", 7, 0);
	if (!ASSERT_EQ(id, 8, "btf__add_decl_tag mixed_owner"))
		goto out;
	id = btf__add_struct(btf, "mixed_node", 32);
	if (!ASSERT_EQ(id, 9, "btf__add_struct mixed_node"))
		goto out;
	err = btf__add_field(btf, "node", LIST_NODE, 0, 0);
	if (!ASSERT_OK(err, "btf__add_field mixed_node::node"))
		goto out;
	err = btf__add_field(btf, "owner", 6, 192, 0);
	if (!ASSERT_OK(err, "btf__add_field mixed_node::owner"))
		goto out;

	err = btf__load_into_kernel(btf);
	ASSERT_EQ(err, -ELOOP, "check btf");
out:
	btf__free(btf);
}

static void test_acyclic_depth(int depth, int expected_err)
{
	int ptr_id[MAX_OWNERSHIP_DEPTH + 1];
	int first_struct_id;
	struct btf *btf;
	int id, err, i;

	btf = init_btf();
	if (!ASSERT_OK_PTR(btf, "init_btf"))
		return;
	first_struct_id = 5 + 2 * depth;
	for (i = 0; i < depth; i++) {
		ptr_id[i] = add_local_kptr(btf, first_struct_id + i + 1, "kptr");
		if (ptr_id[i] <= 0)
			goto out;
	}
	for (i = 0; i < depth; i++) {
		char name[16];

		snprintf(name, sizeof(name), "owner_%d", i);
		id = btf__add_struct(btf, name, 8);
		if (!ASSERT_EQ(id, first_struct_id + i, "btf__add_struct owner"))
			goto out;
		err = btf__add_field(btf, "next", ptr_id[i], 0, 0);
		if (!ASSERT_OK(err, "btf__add_field owner::next"))
			goto out;
	}
	id = btf__add_struct(btf, "plain_leaf", 4);
	if (!ASSERT_EQ(id, first_struct_id + depth, "btf__add_struct plain_leaf"))
		goto out;

	err = btf__load_into_kernel(btf);
	ASSERT_EQ(err, expected_err, "check btf");
out:
	btf__free(btf);
}

void test_local_kptr_ownership(void)
{
	if (test__start_subtest("self_cycle"))
		test_self_cycle("kptr", -ELOOP);
	if (test__start_subtest("untrusted_self_cycle"))
		test_self_cycle("kptr_untrusted", 0);
	if (test__start_subtest("percpu_self_cycle"))
		test_self_cycle("percpu_kptr", -ELOOP);
	if (test__start_subtest("ABA_cycle"))
		test_aba_cycle();
	if (test__start_subtest("mixed_graph_root_cycle"))
		test_mixed_cycle();
	if (test__start_subtest("max_acyclic"))
		test_acyclic_depth(MAX_OWNERSHIP_DEPTH, 0);
	if (test__start_subtest("too_deep_acyclic"))
		test_acyclic_depth(MAX_OWNERSHIP_DEPTH + 1, -ELOOP);
}
