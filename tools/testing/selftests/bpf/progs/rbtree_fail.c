// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_experimental.h"

struct node_data {
	long key;
	long data;
	struct bpf_rb_node node;
};

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
private(A) struct bpf_spin_lock glock;
private(A) struct bpf_rb_root groot __contains(node_data, node);
private(A) struct bpf_rb_root groot2 __contains(node_data, node);

static bool less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct node_data *node_a;
	struct node_data *node_b;

	node_a = container_of(a, struct node_data, node);
	node_b = container_of(b, struct node_data, node);

	return node_a->key < node_b->key;
}

SEC("?tc")
long rbtree_api_nolock_add(void *ctx)
{
	struct node_data *n;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 1;

	bpf_rbtree_add(&groot, &n->node, less);
	return 0;
}

SEC("?tc")
long rbtree_api_nolock_remove(void *ctx)
{
	struct node_data *n;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 1;

	bpf_spin_lock(&glock);
	bpf_rbtree_add(&groot, &n->node, less);
	bpf_spin_unlock(&glock);

	bpf_rbtree_remove(&groot, &n->node);
	return 0;
}

SEC("?tc")
long rbtree_api_nolock_first(void *ctx)
{
	bpf_rbtree_first(&groot);
	return 0;
}

SEC("?tc")
long rbtree_api_remove_unadded_node(void *ctx)
{
	struct node_data *n, *m;
	struct bpf_rb_node *res;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 1;

	m = bpf_obj_new(typeof(*m));
	if (!m) {
		bpf_obj_drop(n);
		return 1;
	}

	bpf_spin_lock(&glock);
	bpf_rbtree_add(&groot, &n->node, less);

	/* This remove should pass verifier */
	res = bpf_rbtree_remove(&groot, &n->node);
	if (res)
		n = container_of(res, struct node_data, node);

	/* This remove shouldn't, m isn't in an rbtree */
	res = bpf_rbtree_remove(&groot, &m->node);
	if (res)
		m = container_of(res, struct node_data, node);
	bpf_spin_unlock(&glock);

	if (n)
		bpf_obj_drop(n);
	if (m)
		bpf_obj_drop(m);
	return 0;
}

SEC("?tc")
long rbtree_api_remove_no_drop(void *ctx)
{
	struct bpf_rb_node *res;
	struct node_data *n;

	bpf_spin_lock(&glock);
	res = bpf_rbtree_first(&groot);
	if (!res)
		goto unlock_err;

	res = bpf_rbtree_remove(&groot, res);
	if (!res)
		goto unlock_err;

	n = container_of(res, struct node_data, node);
	bpf_spin_unlock(&glock);

	/* bpf_obj_drop(n) is missing here */
	return 0;

unlock_err:
	bpf_spin_unlock(&glock);
	return 1;
}

SEC("?tc")
long rbtree_api_add_to_multiple_trees(void *ctx)
{
	struct node_data *n;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 1;

	bpf_spin_lock(&glock);
	bpf_rbtree_add(&groot, &n->node, less);

	/* This add should fail since n already in groot's tree */
	bpf_rbtree_add(&groot2, &n->node, less);
	bpf_spin_unlock(&glock);
	return 0;
}

SEC("?tc")
long rbtree_api_add_release_unlock_escape(void *ctx)
{
	struct node_data *n;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 1;

	bpf_spin_lock(&glock);
	bpf_rbtree_add(&groot, &n->node, less);
	bpf_spin_unlock(&glock);

	bpf_spin_lock(&glock);
	/* After add() in previous critical section, n should be
	 * release_on_unlock and released after previous spin_unlock,
	 * so should not be possible to use it here
	 */
	bpf_rbtree_remove(&groot, &n->node);
	bpf_spin_unlock(&glock);
	return 0;
}

SEC("?tc")
long rbtree_api_first_release_unlock_escape(void *ctx)
{
	struct bpf_rb_node *res;
	struct node_data *n;

	bpf_spin_lock(&glock);
	res = bpf_rbtree_first(&groot);
	if (res)
		n = container_of(res, struct node_data, node);
	bpf_spin_unlock(&glock);

	bpf_spin_lock(&glock);
	/* After first() in previous critical section, n should be
	 * release_on_unlock and released after previous spin_unlock,
	 * so should not be possible to use it here
	 */
	bpf_rbtree_remove(&groot, &n->node);
	bpf_spin_unlock(&glock);
	return 0;
}

static bool less__bad_fn_call_add(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct node_data *node_a;
	struct node_data *node_b;

	node_a = container_of(a, struct node_data, node);
	node_b = container_of(b, struct node_data, node);
	bpf_rbtree_add(&groot, &node_a->node, less);

	return node_a->key < node_b->key;
}

static bool less__bad_fn_call_remove(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct node_data *node_a;
	struct node_data *node_b;

	node_a = container_of(a, struct node_data, node);
	node_b = container_of(b, struct node_data, node);
	bpf_rbtree_remove(&groot, &node_a->node);

	return node_a->key < node_b->key;
}

static bool less__bad_fn_call_first(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct node_data *node_a;
	struct node_data *node_b;

	node_a = container_of(a, struct node_data, node);
	node_b = container_of(b, struct node_data, node);
	bpf_rbtree_first(&groot);

	return node_a->key < node_b->key;
}

static bool less__bad_fn_call_first_unlock_after(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct node_data *node_a;
	struct node_data *node_b;

	node_a = container_of(a, struct node_data, node);
	node_b = container_of(b, struct node_data, node);
	bpf_rbtree_first(&groot);
	bpf_spin_unlock(&glock);

	return node_a->key < node_b->key;
}

#define RBTREE_API_ADD_BAD_CB(cb_suffix)				\
SEC("?tc")								\
long rbtree_api_add_bad_cb_##cb_suffix(void *ctx)			\
{									\
	struct node_data *n;						\
									\
	n = bpf_obj_new(typeof(*n));					\
	if (!n)								\
		return 1;						\
									\
	bpf_spin_lock(&glock);						\
	bpf_rbtree_add(&groot, &n->node, less__##cb_suffix);		\
	bpf_spin_unlock(&glock);					\
	return 0;							\
}

RBTREE_API_ADD_BAD_CB(bad_fn_call_add);
RBTREE_API_ADD_BAD_CB(bad_fn_call_remove);
RBTREE_API_ADD_BAD_CB(bad_fn_call_first);
RBTREE_API_ADD_BAD_CB(bad_fn_call_first_unlock_after);

char _license[] SEC("license") = "GPL";
