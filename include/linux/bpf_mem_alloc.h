/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */
#ifndef _BPF_MEM_ALLOC_H
#define _BPF_MEM_ALLOC_H
#include <linux/compiler_types.h>
#include <linux/workqueue.h>

struct bpf_mem_cache;
struct bpf_mem_caches;

struct bpf_mem_alloc {
	struct bpf_mem_caches __percpu *caches;
	struct bpf_mem_cache __percpu *cache;
	struct work_struct work;
	void (*ctor)(struct bpf_mem_alloc *ma, void *obj);
	unsigned int flags;
};

/* flags for bpf_mem_alloc_init() */
enum {
	BPF_MA_PERCPU = 1,
	/* Don't reuse freed elements during allocation */
	BPF_MA_NO_REUSE = 2,
};

int bpf_mem_alloc_init(struct bpf_mem_alloc *ma, int size, unsigned int flags,
		       void (*ctor)(struct bpf_mem_alloc *, void *));
void bpf_mem_alloc_destroy(struct bpf_mem_alloc *ma);

/* kmalloc/kfree equivalent: */
void *bpf_mem_alloc(struct bpf_mem_alloc *ma, size_t size);
void bpf_mem_free(struct bpf_mem_alloc *ma, void *ptr);

/* kmem_cache_alloc/free equivalent: */
void *bpf_mem_cache_alloc(struct bpf_mem_alloc *ma);
void bpf_mem_cache_free(struct bpf_mem_alloc *ma, void *ptr);

#endif /* _BPF_MEM_ALLOC_H */
