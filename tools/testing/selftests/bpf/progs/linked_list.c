// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_experimental.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

struct bar {
	struct bpf_list_node node;
	int data;
};

struct foo {
	struct bpf_list_node node;
	struct bpf_list_head head __contains(bar, node);
	struct bpf_spin_lock lock;
	int data;
};

struct map_value {
	struct bpf_list_head head __contains(foo, node);
	struct bpf_spin_lock lock;
	int data;
};

struct array_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct map_value);
	__uint(max_entries, 1);
} array_map SEC(".maps");

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))

private(A) static struct bpf_spin_lock glock;
private(A) static struct bpf_list_head ghead __contains(foo, node);
private(A) static struct bpf_list_head gghead __contains(foo, node);

static __always_inline int list_push_pop(struct bpf_spin_lock *lock,
					 struct bpf_list_head *head, bool leave_in_map)
{
	struct bpf_list_node *n;
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 2;

	bpf_spin_lock(lock);
	n = bpf_list_pop_front(head);
	bpf_spin_unlock(lock);
	if (n) {
		bpf_obj_drop(container_of(n, struct foo, node));
		bpf_obj_drop(f);
		return 3;
	}

	bpf_spin_lock(lock);
	n = bpf_list_pop_back(head);
	bpf_spin_unlock(lock);
	if (n) {
		bpf_obj_drop(container_of(n, struct foo, node));
		bpf_obj_drop(f);
		return 4;
	}


	bpf_spin_lock(lock);
	f->data = 42;
	bpf_list_push_front(head, &f->node);
	bpf_spin_unlock(lock);
	if (leave_in_map)
		return 0;
	bpf_spin_lock(lock);
	n = bpf_list_pop_back(head);
	bpf_spin_unlock(lock);
	if (!n)
		return 5;
	f = container_of(n, struct foo, node);
	if (f->data != 42) {
		bpf_obj_drop(f);
		return 6;
	}

	bpf_spin_lock(lock);
	f->data = 13;
	bpf_list_push_front(head, &f->node);
	bpf_spin_unlock(lock);
	bpf_spin_lock(lock);
	n = bpf_list_pop_front(head);
	bpf_spin_unlock(lock);
	if (!n)
		return 7;
	f = container_of(n, struct foo, node);
	if (f->data != 13) {
		bpf_obj_drop(f);
		return 8;
	}
	bpf_obj_drop(f);

	bpf_spin_lock(lock);
	n = bpf_list_pop_front(head);
	bpf_spin_unlock(lock);
	if (n) {
		bpf_obj_drop(container_of(n, struct foo, node));
		return 9;
	}

	bpf_spin_lock(lock);
	n = bpf_list_pop_back(head);
	bpf_spin_unlock(lock);
	if (n) {
		bpf_obj_drop(container_of(n, struct foo, node));
		return 10;
	}
	return 0;
}


static __always_inline int list_push_pop_multiple(struct bpf_spin_lock *lock,
						  struct bpf_list_head *head, bool leave_in_map)
{
	struct bpf_list_node *n;
	struct foo *f[8], *pf;
	int i;

	for (i = 0; i < ARRAY_SIZE(f); i++) {
		f[i] = bpf_obj_new(typeof(**f));
		if (!f[i])
			return 2;
		f[i]->data = i;
		bpf_spin_lock(lock);
		bpf_list_push_front(head, &f[i]->node);
		bpf_spin_unlock(lock);
	}

	for (i = 0; i < ARRAY_SIZE(f); i++) {
		bpf_spin_lock(lock);
		n = bpf_list_pop_front(head);
		bpf_spin_unlock(lock);
		if (!n)
			return 3;
		pf = container_of(n, struct foo, node);
		if (pf->data != (ARRAY_SIZE(f) - i - 1)) {
			bpf_obj_drop(pf);
			return 4;
		}
		bpf_spin_lock(lock);
		bpf_list_push_back(head, &pf->node);
		bpf_spin_unlock(lock);
	}

	if (leave_in_map)
		return 0;

	for (i = 0; i < ARRAY_SIZE(f); i++) {
		bpf_spin_lock(lock);
		n = bpf_list_pop_back(head);
		bpf_spin_unlock(lock);
		if (!n)
			return 5;
		pf = container_of(n, struct foo, node);
		if (pf->data != i) {
			bpf_obj_drop(pf);
			return 6;
		}
		bpf_obj_drop(pf);
	}
	bpf_spin_lock(lock);
	n = bpf_list_pop_back(head);
	bpf_spin_unlock(lock);
	if (n) {
		bpf_obj_drop(container_of(n, struct foo, node));
		return 7;
	}

	bpf_spin_lock(lock);
	n = bpf_list_pop_front(head);
	bpf_spin_unlock(lock);
	if (n) {
		bpf_obj_drop(container_of(n, struct foo, node));
		return 8;
	}
	return 0;
}

static __always_inline int list_in_list(struct bpf_spin_lock *lock,
					struct bpf_list_head *head, bool leave_in_map)
{
	struct bpf_list_node *n;
	struct bar *ba[8], *b;
	struct foo *f;
	int i;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 2;
	for (i = 0; i < ARRAY_SIZE(ba); i++) {
		b = bpf_obj_new(typeof(*b));
		if (!b) {
			bpf_obj_drop(f);
			return 3;
		}
		b->data = i;
		bpf_spin_lock(&f->lock);
		bpf_list_push_back(&f->head, &b->node);
		bpf_spin_unlock(&f->lock);
	}

	bpf_spin_lock(lock);
	f->data = 42;
	bpf_list_push_front(head, &f->node);
	bpf_spin_unlock(lock);

	if (leave_in_map)
		return 0;

	bpf_spin_lock(lock);
	n = bpf_list_pop_front(head);
	bpf_spin_unlock(lock);
	if (!n)
		return 4;
	f = container_of(n, struct foo, node);
	if (f->data != 42) {
		bpf_obj_drop(f);
		return 5;
	}

	for (i = 0; i < ARRAY_SIZE(ba); i++) {
		bpf_spin_lock(&f->lock);
		n = bpf_list_pop_front(&f->head);
		bpf_spin_unlock(&f->lock);
		if (!n) {
			bpf_obj_drop(f);
			return 6;
		}
		b = container_of(n, struct bar, node);
		if (b->data != i) {
			bpf_obj_drop(f);
			bpf_obj_drop(b);
			return 7;
		}
		bpf_obj_drop(b);
	}
	bpf_spin_lock(&f->lock);
	n = bpf_list_pop_front(&f->head);
	bpf_spin_unlock(&f->lock);
	if (n) {
		bpf_obj_drop(f);
		bpf_obj_drop(container_of(n, struct bar, node));
		return 8;
	}
	bpf_obj_drop(f);
	return 0;
}

SEC("tc")
int map_list_push_pop(void *ctx)
{
	struct map_value *v;

	v = bpf_map_lookup_elem(&array_map, &(int){0});
	if (!v)
		return 1;
	return list_push_pop(&v->lock, &v->head, false);
}

SEC("tc")
int global_list_push_pop(void *ctx)
{
	return list_push_pop(&glock, &ghead, false);
}

SEC("tc")
int global_list_push_pop_unclean(void *ctx)
{
	return list_push_pop(&glock, &gghead, true);
}

SEC("tc")
int map_list_push_pop_multiple(void *ctx)
{
	struct map_value *v;

	v = bpf_map_lookup_elem(&array_map, &(int){0});
	if (!v)
		return 1;
	return list_push_pop_multiple(&v->lock, &v->head, false);
}

SEC("tc")
int global_list_push_pop_multiple(void *ctx)
{
	return list_push_pop_multiple(&glock, &ghead, false);
}

SEC("tc")
int global_list_push_pop_multiple_unclean(void *ctx)
{
	return list_push_pop_multiple(&glock, &gghead, true);
}

SEC("tc")
int map_list_in_list(void *ctx)
{
	struct map_value *v;

	v = bpf_map_lookup_elem(&array_map, &(int){0});
	if (!v)
		return 1;
	return list_in_list(&v->lock, &v->head, false);
}

SEC("tc")
int global_list_in_list(void *ctx)
{
	return list_in_list(&glock, &ghead, false);
}

SEC("tc")
int global_list_in_list_unclean(void *ctx)
{
	return list_in_list(&glock, &gghead, true);
}

char _license[] SEC("license") = "GPL";
