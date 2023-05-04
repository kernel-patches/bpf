// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

struct node_data {
	long key;
	long list_data;
	struct bpf_rb_node r;
	struct bpf_list_node l;
	struct bpf_refcount ref;
};

struct map_value {
	struct node_data __kptr *node;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct map_value);
	__uint(max_entries, 1);
} stashed_nodes SEC(".maps");

struct node_acquire {
	long key;
	long data;
	struct bpf_rb_node node;
	struct bpf_refcount refcount;
};

#define private(name) SEC(".bss." #name) __hidden __attribute__((aligned(8)))
private(A) struct bpf_spin_lock lock;
private(A) struct bpf_rb_root root __contains(node_data, r);
private(A) struct bpf_list_head head __contains(node_data, l);

private(C) struct bpf_spin_lock lock2;
private(C) struct bpf_rb_root root2 __contains(node_data, r);

private(B) struct bpf_spin_lock alock;
private(B) struct bpf_rb_root aroot __contains(node_acquire, node);

private(D) struct bpf_spin_lock ref_acq_lock;
private(E) struct bpf_spin_lock rem_node_lock;

/* Provided by bpf_testmod */
extern void bpf__unsafe_spin_lock(void *lock__ign) __ksym;
extern void bpf__unsafe_spin_unlock(void *lock__ign) __ksym;
extern volatile int bpf_refcount_read(void *refcount__ign) __ksym;

static bool less(struct bpf_rb_node *node_a, const struct bpf_rb_node *node_b)
{
	struct node_data *a;
	struct node_data *b;

	a = container_of(node_a, struct node_data, r);
	b = container_of(node_b, struct node_data, r);

	return a->key < b->key;
}

static bool less_a(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct node_acquire *node_a;
	struct node_acquire *node_b;

	node_a = container_of(a, struct node_acquire, node);
	node_b = container_of(b, struct node_acquire, node);

	return node_a->key < node_b->key;
}

static long __insert_in_tree_and_list(struct bpf_list_head *head,
				      struct bpf_rb_root *root,
				      struct bpf_spin_lock *lock)
{
	struct node_data *n, *m;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return -1;

	m = bpf_refcount_acquire(n);
	m->key = 123;
	m->list_data = 456;

	bpf_spin_lock(lock);
	if (bpf_rbtree_add(root, &n->r, less)) {
		/* Failure to insert - unexpected */
		bpf_spin_unlock(lock);
		bpf_obj_drop(m);
		return -2;
	}
	bpf_spin_unlock(lock);

	bpf_spin_lock(lock);
	if (bpf_list_push_front(head, &m->l)) {
		/* Failure to insert - unexpected */
		bpf_spin_unlock(lock);
		return -3;
	}
	bpf_spin_unlock(lock);
	return 0;
}

static long __stash_map_insert_tree(int idx, int val, struct bpf_rb_root *root,
				    struct bpf_spin_lock *lock)
{
	struct map_value *mapval;
	struct node_data *n, *m;

	mapval = bpf_map_lookup_elem(&stashed_nodes, &idx);
	if (!mapval)
		return -1;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return -2;

	n->key = val;
	m = bpf_refcount_acquire(n);

	n = bpf_kptr_xchg(&mapval->node, n);
	if (n) {
		bpf_obj_drop(n);
		bpf_obj_drop(m);
		return -3;
	}

	bpf_spin_lock(lock);
	if (bpf_rbtree_add(root, &m->r, less)) {
		/* Failure to insert - unexpected */
		bpf_spin_unlock(lock);
		return -4;
	}
	bpf_spin_unlock(lock);
	return 0;
}

static long __read_from_tree(struct bpf_rb_root *root,
			     struct bpf_spin_lock *lock,
			     bool remove_from_tree)
{
	struct bpf_rb_node *rb;
	struct node_data *n;
	long res = -99;

	bpf_spin_lock(lock);

	rb = bpf_rbtree_first(root);
	if (!rb) {
		bpf_spin_unlock(lock);
		return -1;
	}

	n = container_of(rb, struct node_data, r);
	res = n->key;

	if (!remove_from_tree) {
		bpf_spin_unlock(lock);
		return res;
	}

	rb = bpf_rbtree_remove(root, rb);
	bpf_spin_unlock(lock);
	if (!rb)
		return -2;
	n = container_of(rb, struct node_data, r);
	bpf_obj_drop(n);
	return res;
}

static long __read_from_list(struct bpf_list_head *head,
			     struct bpf_spin_lock *lock,
			     bool remove_from_list)
{
	struct bpf_list_node *l;
	struct node_data *n;
	long res = -99;

	bpf_spin_lock(lock);

	l = bpf_list_pop_front(head);
	if (!l) {
		bpf_spin_unlock(lock);
		return -1;
	}

	n = container_of(l, struct node_data, l);
	res = n->list_data;

	if (!remove_from_list) {
		if (bpf_list_push_back(head, &n->l)) {
			bpf_spin_unlock(lock);
			return -2;
		}
	}

	bpf_spin_unlock(lock);

	if (remove_from_list)
		bpf_obj_drop(n);
	return res;
}

static long __read_from_unstash(int idx)
{
	struct node_data *n = NULL;
	struct map_value *mapval;
	long val = -99;

	mapval = bpf_map_lookup_elem(&stashed_nodes, &idx);
	if (!mapval)
		return -1;

	n = bpf_kptr_xchg(&mapval->node, n);
	if (!n)
		return -2;

	val = n->key;
	bpf_obj_drop(n);
	return val;
}

#define INSERT_READ_BOTH(rem_tree, rem_list, desc)			\
SEC("tc")								\
__description(desc)							\
__success __retval(579)							\
long insert_and_remove_tree_##rem_tree##_list_##rem_list(void *ctx)	\
{									\
	long err, tree_data, list_data;					\
									\
	err = __insert_in_tree_and_list(&head, &root, &lock);		\
	if (err)							\
		return err;						\
									\
	err = __read_from_tree(&root, &lock, rem_tree);			\
	if (err < 0)							\
		return err;						\
	else								\
		tree_data = err;					\
									\
	err = __read_from_list(&head, &lock, rem_list);			\
	if (err < 0)							\
		return err;						\
	else								\
		list_data = err;					\
									\
	return tree_data + list_data;					\
}

/* After successful insert of struct node_data into both collections:
 *   - it should have refcount = 2
 *   - removing / not removing the node_data from a collection after
 *     reading should have no effect on ability to read / remove from
 *     the other collection
 */
INSERT_READ_BOTH(true, true, "insert_read_both: remove from tree + list");
INSERT_READ_BOTH(false, false, "insert_read_both: remove from neither");
INSERT_READ_BOTH(true, false, "insert_read_both: remove from tree");
INSERT_READ_BOTH(false, true, "insert_read_both: remove from list");

#undef INSERT_READ_BOTH
#define INSERT_READ_BOTH(rem_tree, rem_list, desc)			\
SEC("tc")								\
__description(desc)							\
__success __retval(579)							\
long insert_and_remove_lf_tree_##rem_tree##_list_##rem_list(void *ctx)	\
{									\
	long err, tree_data, list_data;					\
									\
	err = __insert_in_tree_and_list(&head, &root, &lock);		\
	if (err)							\
		return err;						\
									\
	err = __read_from_list(&head, &lock, rem_list);			\
	if (err < 0)							\
		return err;						\
	else								\
		list_data = err;					\
									\
	err = __read_from_tree(&root, &lock, rem_tree);			\
	if (err < 0)							\
		return err;						\
	else								\
		tree_data = err;					\
									\
	return tree_data + list_data;					\
}

/* Similar to insert_read_both, but list data is read and possibly removed
 * first
 *
 * Results should be no different than reading and possibly removing rbtree
 * node first
 */
INSERT_READ_BOTH(true, true, "insert_read_both_list_first: remove from tree + list");
INSERT_READ_BOTH(false, false, "insert_read_both_list_first: remove from neither");
INSERT_READ_BOTH(true, false, "insert_read_both_list_first: remove from tree");
INSERT_READ_BOTH(false, true, "insert_read_both_list_first: remove from list");

#define INSERT_DOUBLE_READ_AND_DEL(read_fn, read_root, desc)		\
SEC("tc")								\
__description(desc)							\
__success __retval(-1)							\
long insert_double_##read_fn##_and_del_##read_root(void *ctx)		\
{									\
	long err, list_data;						\
									\
	err = __insert_in_tree_and_list(&head, &root, &lock);		\
	if (err)							\
		return err;						\
									\
	err = read_fn(&read_root, &lock, true);				\
	if (err < 0)							\
		return err;						\
	else								\
		list_data = err;					\
									\
	err = read_fn(&read_root, &lock, true);				\
	if (err < 0)							\
		return err;						\
									\
	return err + list_data;						\
}

/* Insert into both tree and list, then try reading-and-removing from either twice
 *
 * The second read-and-remove should fail on read step since the node has
 * already been removed
 */
INSERT_DOUBLE_READ_AND_DEL(__read_from_tree, root, "insert_double_del: 2x read-and-del from tree");
INSERT_DOUBLE_READ_AND_DEL(__read_from_list, head, "insert_double_del: 2x read-and-del from list");

#define INSERT_STASH_READ(rem_tree, desc)				\
SEC("tc")								\
__description(desc)							\
__success __retval(84)							\
long insert_rbtree_and_stash__del_tree_##rem_tree(void *ctx)		\
{									\
	long err, tree_data, map_data;					\
									\
	err = __stash_map_insert_tree(0, 42, &root, &lock);		\
	if (err)							\
		return err;						\
									\
	err = __read_from_tree(&root, &lock, rem_tree);			\
	if (err < 0)							\
		return err;						\
	else								\
		tree_data = err;					\
									\
	err = __read_from_unstash(0);					\
	if (err < 0)							\
		return err;						\
	else								\
		map_data = err;						\
									\
	return tree_data + map_data;					\
}

/* Stash a refcounted node in map_val, insert same node into tree, then try
 * reading data from tree then unstashed map_val, possibly removing from tree
 *
 * Removing from tree should have no effect on map_val kptr validity
 */
INSERT_STASH_READ(true, "insert_stash_read: remove from tree");
INSERT_STASH_READ(false, "insert_stash_read: don't remove from tree");

SEC("tc")
__success
long rbtree_refcounted_node_ref_escapes(void *ctx)
{
	struct node_acquire *n, *m;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 1;

	bpf_spin_lock(&alock);
	bpf_rbtree_add(&aroot, &n->node, less_a);
	m = bpf_refcount_acquire(n);
	bpf_spin_unlock(&alock);
	if (!m)
		return 2;

	m->key = 2;
	bpf_obj_drop(m);
	return 0;
}

SEC("tc")
__success
long rbtree_refcounted_node_ref_escapes_owning_input(void *ctx)
{
	struct node_acquire *n, *m;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 1;

	m = bpf_refcount_acquire(n);
	m->key = 2;

	bpf_spin_lock(&alock);
	bpf_rbtree_add(&aroot, &n->node, less_a);
	bpf_spin_unlock(&alock);

	bpf_obj_drop(m);

	return 0;
}

SEC("tc")
long unsafe_ref_acq_lock(void *ctx)
{
	bpf__unsafe_spin_lock(&ref_acq_lock);
	return 0;
}

SEC("tc")
long unsafe_ref_acq_unlock(void *ctx)
{
	bpf__unsafe_spin_unlock(&ref_acq_lock);
	return 0;
}

SEC("tc")
long unsafe_rem_node_lock(void *ctx)
{
	bpf__unsafe_spin_lock(&rem_node_lock);
	return 0;
}

/* The following 3 progs are used in concert to test a bpf_refcount-related
 * race. Consider the following pseudocode interleaving of rbtree operations:
 *
 * (Assumptions: n, m, o, p, q are pointers to nodes, t1 and t2 are different
 * rbtrees, l1 and l2 are locks accompanying the trees, mapval is some
 * kptr_xchg'able ptr_to_map_value. A single node is being manipulated by both
 * programs. Irrelevant error-checking and casting is omitted.)
 *
 *               CPU O                               CPU 1
 *     ----------------------------------|---------------------------
 *     n = bpf_obj_new  [0]              |
 *     lock(l1)                          |
 *     bpf_rbtree_add(t1, &n->r, less)   |
 *     m = bpf_refcount_acquire(n)  [1]  |
 *     unlock(l1)                        |
 *     kptr_xchg(mapval, m)         [2]  |
 *     --------------------------------------------------------------
 *                                       |    o = kptr_xchg(mapval, NULL)  [3]
 *                                       |    lock(l2)
 *                                       |    rbtree_add(t2, &o->r, less)  [4]
 *     --------------------------------------------------------------
 *     lock(l1)                          |
 *     p = rbtree_first(t1)              |
 *     p = rbtree_remove(t1, p)          |
 *     unlock(l1)                        |
 *     if (p)                            |
 *       bpf_obj_drop(p)  [5]            |
 *     --------------------------------------------------------------
 *                                       |    q = bpf_refcount_acquire(o)  [6]
 *                                       |    unlock(l2)
 *
 * If bpf_refcount_acquire can't fail, the sequence of operations on the node's
 * refcount is:
 *    [0] - refcount initialized to 1
 *    [1] - refcount bumped to 2
 *    [2] - refcount is still 2, but m's ownership passed to mapval
 *    [3] - refcount is still 2, mapval's ownership passed to o
 *    [4] - refcount is decr'd to 1, rbtree_add fails, node is already in t1
 *          o is converted to non-owning reference
 *    [5] - refcount is decr'd to 0, node free'd
 *    [6] - refcount is incr'd to 1 from 0, ERROR
 *
 * To prevent [6] bpf_refcount_acquire was made failable. This interleaving is
 * used to test failable refcount_acquire.
 *
 * The two halves of CPU 0's operations are implemented by
 * add_refcounted_node_to_tree_and_stash and remove_refcounted_node_from_tree.
 * We can't do the same for CPU 1's operations due to l2 critical section.
 * Instead, bpf__unsafe_spin_{lock, unlock} are used to ensure the expected
 * order of operations.
 */

SEC("tc")
long add_refcounted_node_to_tree_and_stash(void *ctx)
{
	long err;

	err = __stash_map_insert_tree(0, 42, &root, &lock);
	if (err)
		return err;

	return 0;
}

SEC("tc")
long remove_refcounted_node_from_tree(void *ctx)
{
	long ret = 0;

	/* rem_node_lock is held by another program to force race */
	bpf__unsafe_spin_lock(&rem_node_lock);
	ret = __read_from_tree(&root, &lock, true);
	if (ret != 42)
		return ret;

	bpf__unsafe_spin_unlock(&rem_node_lock);
	return 0;
}

/* ref_check_n numbers correspond to refcount operation points in comment above */
int ref_check_3, ref_check_4, ref_check_5;

SEC("tc")
long unstash_add_and_acquire_refcount(void *ctx)
{
	struct map_value *mapval;
	struct node_data *n, *m;
	int idx = 0;

	mapval = bpf_map_lookup_elem(&stashed_nodes, &idx);
	if (!mapval)
		return -1;

	n = bpf_kptr_xchg(&mapval->node, NULL);
	if (!n)
		return -2;
	ref_check_3 = bpf_refcount_read(&n->ref);

	bpf_spin_lock(&lock2);
	bpf_rbtree_add(&root2, &n->r, less);
	ref_check_4 = bpf_refcount_read(&n->ref);

	/* Let CPU 0 do first->remove->drop */
	bpf__unsafe_spin_unlock(&rem_node_lock);

	/* ref_acq_lock is held by another program to force race
	 * when this program holds the lock, remove_refcounted_node_from_tree
	 * has finished
	 */
	bpf__unsafe_spin_lock(&ref_acq_lock);
	ref_check_5 = bpf_refcount_read(&n->ref);

	/* Error-causing use-after-free incr ([6] in long comment above) */
	m = bpf_refcount_acquire(n);
	bpf__unsafe_spin_unlock(&ref_acq_lock);

	bpf_spin_unlock(&lock2);

	if (m) {
		bpf_obj_drop(m);
		return -3;
	}

	return !!m;
}

char _license[] SEC("license") = "GPL";
