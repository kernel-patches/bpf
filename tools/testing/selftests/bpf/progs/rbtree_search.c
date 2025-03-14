// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

struct node_data {
	struct bpf_rb_node rb_node;
	int key;
};

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
private(A) struct bpf_spin_lock glock;
private(A) struct bpf_rb_root groot __contains(node_data, rb_node);

#define rb_entry(ptr, type, member) container_of(ptr, type, member)
#define NR_NODES 16

int zero = 0;

static bool less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct node_data *node_a;
	struct node_data *node_b;

	node_a = rb_entry(a, struct node_data, rb_node);
	node_b = rb_entry(b, struct node_data, rb_node);

	return node_a->key < node_b->key;
}

SEC("syscall")
__retval(0)
long rbtree_search(void *ctx)
{
	struct bpf_rb_node *rb_n, *gc_ns[NR_NODES];
	long lookup_key = NR_NODES / 2;
	struct node_data *n;
	int i, err, nr_gc = 0;

	for (i = zero; i < NR_NODES && can_loop; i++) {
		n = bpf_obj_new(typeof(*n));
		if (!n)
			return __LINE__;
		n->key = i;
		bpf_spin_lock(&glock);
		err = bpf_rbtree_add(&groot, &n->rb_node, less);
		bpf_spin_unlock(&glock);

		if (err)
			return __LINE__;
	}

	n = NULL;
	bpf_spin_lock(&glock);
	rb_n = bpf_rbtree_root(&groot);
	while (can_loop) {
		if (!rb_n) {
			bpf_spin_unlock(&glock);
			return __LINE__;
		}

		n = rb_entry(rb_n, struct node_data, rb_node);
		if (lookup_key == n->key)
			break;
		if (nr_gc < NR_NODES)
			gc_ns[nr_gc++] = rb_n;
		if (lookup_key < n->key)
			rb_n = bpf_rbtree_left(&groot, rb_n);
		else
			rb_n = bpf_rbtree_right(&groot, rb_n);
	}

	if (!n || lookup_key != n->key) {
		bpf_spin_unlock(&glock);
		return __LINE__;
	}

	for (i = 0; i < nr_gc; i++) {
		rb_n = gc_ns[i];
		gc_ns[i] = bpf_rbtree_remove(&groot, rb_n);
	}
	bpf_spin_unlock(&glock);

	for (i = 0; i < nr_gc; i++) {
		rb_n = gc_ns[i];
		if (rb_n) {
			n = rb_entry(rb_n, struct node_data, rb_node);
			bpf_obj_drop(n);
		}
	}

	while (can_loop) {
		bpf_spin_lock(&glock);
		rb_n = bpf_rbtree_first(&groot);
		if (rb_n)
			rb_n = bpf_rbtree_remove(&groot, rb_n);
		bpf_spin_unlock(&glock);
		if (!rb_n)
			break;

		n = rb_entry(rb_n, struct node_data, rb_node);
		bpf_obj_drop(n);
	}

	bpf_spin_lock(&glock);
	rb_n = bpf_rbtree_root(&groot);
	bpf_spin_unlock(&glock);
	if (rb_n)
		return __LINE__;

	return 0;
}

char _license[] SEC("license") = "GPL";
