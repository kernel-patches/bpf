// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 KylinSoft Corporation. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

#define NR_NODES 16

struct node_data {
	int data;
};

struct tree_node {
	struct bpf_rb_node node;
	u64 key;
	struct node_data __kptr * node_data;
};

#define private(name) SEC(".data." #name) __hidden __aligned(8)

private(A) struct bpf_rb_root root __contains(tree_node, node);
private(A) struct bpf_spin_lock lock;

static bool less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct tree_node *node_a, *node_b;

	node_a = container_of(a, struct tree_node, node);
	node_b = container_of(b, struct tree_node, node);

	return node_a->key < node_b->key;
}

SEC("syscall")
__retval(0)
long rbtree_search_kptr(void *ctx)
{
	struct tree_node *tnode;
	struct bpf_rb_node *rb_n;
	struct node_data __kptr * node_data;
	int lookup_key  = NR_NODES / 2;
	int lookup_data = NR_NODES / 2;
	int i, data, ret = 0;

	for (i = 0; i < NR_NODES && can_loop; i++) {
		tnode = bpf_obj_new(typeof(*tnode));
		if (!tnode)
			return __LINE__;

		node_data = bpf_obj_new(typeof(*node_data));
		if (!node_data) {
			bpf_obj_drop(tnode);
			return __LINE__;
		}

		tnode->key = i;
		node_data->data = i;

		node_data = bpf_kptr_xchg(&tnode->node_data, node_data);
		if (node_data)
			bpf_obj_drop(node_data);

		bpf_spin_lock(&lock);
		bpf_rbtree_add(&root, &tnode->node, less);
		bpf_spin_unlock(&lock);
	}

	bpf_spin_lock(&lock);
	rb_n = bpf_rbtree_root(&root);
	while (rb_n && can_loop) {
		tnode = container_of(rb_n, struct tree_node, node);
		node_data = bpf_kptr_xchg(&tnode->node_data, NULL);
		if (!node_data) {
			ret = __LINE__;
			goto fail;
		}

		data = node_data->data;
		node_data = bpf_kptr_xchg(&tnode->node_data, node_data);
		if (node_data) {
			bpf_spin_unlock(&lock);
			bpf_obj_drop(node_data);
			return __LINE__;
		}

		if (lookup_key == tnode->key) {
			if (data == lookup_data)
				break;

			ret = __LINE__;
			goto fail;
		}

		if (lookup_key < tnode->key)
			rb_n = bpf_rbtree_left(&root, rb_n);
		else
			rb_n = bpf_rbtree_right(&root, rb_n);
	}
	bpf_spin_unlock(&lock);

	while (can_loop) {
		bpf_spin_lock(&lock);
		rb_n = bpf_rbtree_first(&root);
		if (!rb_n) {
			bpf_spin_unlock(&lock);
			return 0;
		}

		rb_n = bpf_rbtree_remove(&root, rb_n);
		if (!rb_n) {
			ret = __LINE__;
			goto fail;
		}
		bpf_spin_unlock(&lock);

		tnode = container_of(rb_n, struct tree_node, node);

		node_data = bpf_kptr_xchg(&tnode->node_data, NULL);
		if (node_data)
			bpf_obj_drop(node_data);

		bpf_obj_drop(tnode);
	}

	return 0;
fail:
	bpf_spin_unlock(&lock);
	return ret;
}


SEC("syscall")
__failure __msg("R1 type=scalar expected=map_value, ptr_, ptr_")
long non_own_ref_kptr_xchg_no_lock(void *ctx)
{
	struct tree_node *tnode;
	struct bpf_rb_node *rb_n;
	struct node_data __kptr * node_data;
	int data;

	bpf_spin_lock(&lock);
	rb_n = bpf_rbtree_first(&root);
	if (!rb_n) {
		bpf_spin_unlock(&lock);
		return __LINE__;
	}
	bpf_spin_unlock(&lock);

	tnode = container_of(rb_n, struct tree_node, node);
	node_data = bpf_kptr_xchg(&tnode->node_data, NULL);
	if (!node_data)
		return __LINE__;

	data = node_data->data;
	if (data < 0)
		return __LINE__;

	node_data = bpf_kptr_xchg(&tnode->node_data, node_data);
	if (node_data)
		return __LINE__;

	return 0;
}

char _license[] SEC("license") = "GPL";
