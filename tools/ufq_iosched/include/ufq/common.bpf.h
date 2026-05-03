/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 KylinSoft Corporation.
 * Copyright (c) 2026 Kaitao Cheng <chengkaitao@kylinos.cn>
 */
#ifndef __UFQ_COMMON_BPF_H
#define __UFQ_COMMON_BPF_H

#ifdef LSP
#define __bpf__
#include "../vmlinux/vmlinux.h"
#else
#include "vmlinux.h"
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <asm-generic/errno.h>
#include "simple_stat.h"

#define BPF_STRUCT_OPS(name, args...)					\
	SEC("struct_ops/" #name) BPF_PROG(name, ##args)

/* Define struct ufq_iosched_ops for .struct_ops.link in the BPF object */
#define UFQ_OPS_DEFINE(__name, ...)					\
	SEC(".struct_ops.link")						\
	struct ufq_iosched_ops __name = {				\
		__VA_ARGS__,						\
	}

/* list and rbtree */
#define __contains(name, node) __attribute__((btf_decl_tag("contains:" #name ":" #node)))

struct request *bpf_request_acquire(struct request *rq) __ksym;
void bpf_request_release(struct request *rq) __ksym;
bool bpf_request_bio_try_merge(struct request *rq, struct bio *bio,
			       unsigned int nr_segs) __ksym;
struct request *bpf_request_try_merge(struct request *rq, struct request *next) __ksym;

void *bpf_obj_new_impl(__u64 local_type_id, void *meta) __ksym;
void bpf_obj_drop_impl(void *kptr, void *meta) __ksym;

#define bpf_obj_new(type) ((type *)bpf_obj_new_impl(bpf_core_type_id_local(type), NULL))
#define bpf_obj_drop(kptr) bpf_obj_drop_impl(kptr, NULL)

int bpf_list_push_front_impl(struct bpf_list_head *head,
				    struct bpf_list_node *node,
				    void *meta, __u64 off) __ksym;
#define bpf_list_push_front(head, node) bpf_list_push_front_impl(head, node, NULL, 0)

int bpf_list_push_back_impl(struct bpf_list_head *head,
				   struct bpf_list_node *node,
				   void *meta, __u64 off) __ksym;
#define bpf_list_push_back(head, node) bpf_list_push_back_impl(head, node, NULL, 0)

struct bpf_list_node *bpf_list_pop_front(struct bpf_list_head *head) __ksym;
struct bpf_list_node *bpf_list_pop_back(struct bpf_list_head *head) __ksym;
bool bpf_list_empty(struct bpf_list_head *head) __ksym;
struct bpf_list_node *bpf_list_del(struct bpf_list_head *head,
				   struct bpf_list_node *node) __ksym;

struct bpf_rb_node *bpf_rbtree_remove(struct bpf_rb_root *root,
				      struct bpf_rb_node *node) __ksym;
int bpf_rbtree_add_impl(struct bpf_rb_root *root, struct bpf_rb_node *node,
			bool (less)(struct bpf_rb_node *a, const struct bpf_rb_node *b),
			void *meta, __u64 off) __ksym;
#define bpf_rbtree_add(head, node, less) bpf_rbtree_add_impl(head, node, less, NULL, 0)

struct bpf_rb_node *bpf_rbtree_first(struct bpf_rb_root *root) __ksym;

void *bpf_refcount_acquire_impl(void *kptr, void *meta) __ksym;
#define bpf_refcount_acquire(kptr) bpf_refcount_acquire_impl(kptr, NULL)

#endif	/* __UFQ_COMMON_BPF_H */
