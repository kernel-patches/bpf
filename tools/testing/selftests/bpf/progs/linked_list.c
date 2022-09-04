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
	struct bpf_list_node node __kernel;
	int data;
};

struct foo {
	struct bpf_list_node node __kernel;
	struct bpf_list_head head __kernel __contains(struct, bar, node);
	struct bpf_spin_lock lock __kernel;
	int data;
};

struct map_value {
	struct bpf_list_head head __contains(struct, foo, node);
	struct bpf_spin_lock lock;
	int data;
};

struct array_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct map_value);
	__uint(max_entries, 1);
} array_map SEC(".maps");

struct bpf_spin_lock glock SEC(".bss.private");
struct bpf_list_head ghead __contains(struct, foo, node) SEC(".bss.private");
struct bpf_list_head gghead __contains(struct, foo, node) SEC(".bss.private");

static struct foo *foo_alloc(void)
{
	struct foo *f;

	f = bpf_kptr_alloc(bpf_core_type_id_local(struct foo), 0);
	if (!f)
		return NULL;
	bpf_list_node_init(&f->node);
	bpf_list_head_init(&f->head);
	bpf_spin_lock_init(&f->lock);
	return f;
}

static void foo_free(struct foo *f)
{
	if (!f)
		return;
	bpf_list_head_fini(&f->head, offsetof(struct bar, node));
	bpf_kptr_free(f);
}

static __always_inline int list_push_pop(void *lock, void *head, bool leave_in_map)
{
	struct bpf_list_node *n;
	struct foo *f;

	f = foo_alloc();
	if (!f)
		return 2;

	bpf_spin_lock(lock);
	n = bpf_list_pop_front(head);
	bpf_spin_unlock(lock);
	if (n) {
		foo_free(container_of(n, struct foo, node));
		foo_free(f);
		return 3;
	}

	bpf_spin_lock(lock);
	n = bpf_list_pop_back(head);
	bpf_spin_unlock(lock);
	if (n) {
		foo_free(container_of(n, struct foo, node));
		foo_free(f);
		return 4;
	}


	bpf_spin_lock(lock);
	bpf_list_add(&f->node, head);
	f->data = 42;
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
		foo_free(f);
		return 6;
	}

	bpf_spin_lock(lock);
	bpf_list_add(&f->node, head);
	f->data = 13;
	bpf_spin_unlock(lock);
	bpf_spin_lock(lock);
	n = bpf_list_pop_front(head);
	bpf_spin_unlock(lock);
	if (!n)
		return 7;
	f = container_of(n, struct foo, node);
	if (f->data != 13) {
		foo_free(f);
		return 8;
	}
	foo_free(f);

	bpf_spin_lock(lock);
	n = bpf_list_pop_front(head);
	bpf_spin_unlock(lock);
	if (n) {
		foo_free(container_of(n, struct foo, node));
		return 9;
	}

	bpf_spin_lock(lock);
	n = bpf_list_pop_back(head);
	bpf_spin_unlock(lock);
	if (n) {
		foo_free(container_of(n, struct foo, node));
		return 10;
	}
	return 0;
}


static __always_inline int list_push_pop_multiple(void *lock, void *head, bool leave_in_map)
{
	struct bpf_list_node *n;
	struct foo *f[8], *pf;
	int i;

	for (i = 0; i < ARRAY_SIZE(f); i++) {
		f[i] = foo_alloc();
		if (!f[i])
			return 2;
		f[i]->data = i;
		bpf_spin_lock(lock);
		bpf_list_add(&f[i]->node, head);
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
			foo_free(pf);
			return 4;
		}
		bpf_spin_lock(lock);
		bpf_list_add_tail(&pf->node, head);
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
			foo_free(pf);
			return 6;
		}
		foo_free(pf);
	}
	bpf_spin_lock(lock);
	n = bpf_list_pop_back(head);
	bpf_spin_unlock(lock);
	if (n) {
		foo_free(container_of(n, struct foo, node));
		return 7;
	}

	bpf_spin_lock(lock);
	n = bpf_list_pop_front(head);
	bpf_spin_unlock(lock);
	if (n) {
		foo_free(container_of(n, struct foo, node));
		return 8;
	}
	return 0;
}

static __always_inline int list_in_list(void *lock, void *head, bool leave_in_map)
{
	struct bpf_list_node *n;
	struct bar *ba[8], *b;
	struct foo *f;
	int i;

	f = foo_alloc();
	if (!f)
		return 2;
	for (i = 0; i < ARRAY_SIZE(ba); i++) {
		b = bpf_kptr_alloc(bpf_core_type_id_local(struct bar), 0);
		if (!b) {
			foo_free(f);
			return 3;
		}
		bpf_list_node_init(&b->node);
		b->data = i;
		bpf_spin_lock(&f->lock);
		bpf_list_add_tail(&b->node, &f->head);
		bpf_spin_unlock(&f->lock);
	}

	bpf_spin_lock(lock);
	bpf_list_add(&f->node, head);
	f->data = 42;
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
		foo_free(f);
		return 5;
	}

	for (i = 0; i < ARRAY_SIZE(ba); i++) {
		bpf_spin_lock(&f->lock);
		n = bpf_list_pop_front(&f->head);
		bpf_spin_unlock(&f->lock);
		if (!n) {
			foo_free(f);
			return 6;
		}
		b = container_of(n, struct bar, node);
		if (b->data != i) {
			foo_free(f);
			bpf_kptr_free(b);
			return 7;
		}
		bpf_kptr_free(b);
	}
	bpf_spin_lock(&f->lock);
	n = bpf_list_pop_front(&f->head);
	bpf_spin_unlock(&f->lock);
	if (n) {
		foo_free(f);
		bpf_kptr_free(container_of(n, struct bar, node));
		return 8;
	}
	foo_free(f);
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
