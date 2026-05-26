// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf_atomic.h>

#define BIT(nr)			(1UL << (nr))

#define ___GFP_IO		BIT(___GFP_IO_BIT)
#define ___GFP_FS		BIT(___GFP_FS_BIT)
#define ___GFP_DIRECT_RECLAIM	BIT(___GFP_DIRECT_RECLAIM_BIT)
#define ___GFP_KSWAPD_RECLAIM	BIT(___GFP_KSWAPD_RECLAIM_BIT)

#define __GFP_IO	((gfp_t)___GFP_IO)
#define __GFP_FS	((gfp_t)___GFP_FS)
#define __GFP_DIRECT_RECLAIM	((gfp_t)___GFP_DIRECT_RECLAIM) /* Caller can reclaim */
#define __GFP_KSWAPD_RECLAIM	((gfp_t)___GFP_KSWAPD_RECLAIM) /* kswapd can wake */
#define __GFP_RECLAIM ((gfp_t)(___GFP_DIRECT_RECLAIM|___GFP_KSWAPD_RECLAIM))

#define GFP_KERNEL	(__GFP_RECLAIM | __GFP_IO | __GFP_FS)

#define ONE_MB_PAGE_COUNT 256

struct bpf_args_s {
	u64 cgroup_id;
	u64 limit_bytes;
} bpf_args;

struct wq_elem {
	struct bpf_wq work;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct wq_elem);
} wq_map SEC(".maps");

static s64 allocated;
static s64 old_allocated;
static u64 async_free_run;
static u64 initialize_status = 1;

struct cgroup_memcg {
	struct cgroup *cgrp;
	struct mem_cgroup *memcg;
};

static int get_cgroup_memcg_from_id(u64 cgroup_id, struct cgroup_memcg *cm)
{
	cm->cgrp = bpf_cgroup_from_id(cgroup_id);
	if (!cm->cgrp)
		return -1;

	cm->memcg = bpf_get_mem_cgroup(&cm->cgrp->self);
	if (!cm->memcg) {
		bpf_cgroup_release(cm->cgrp);
		return -1;
	}

	return 0;
}

static void put_cgroup_memcg(struct cgroup_memcg *cm)
{
	bpf_put_mem_cgroup(cm->memcg);
	bpf_cgroup_release(cm->cgrp);
}

static int async_free(void *map, int *key, void *value)
{
	struct cgroup_memcg cm;
	bool started_wq = false;

	if (get_cgroup_memcg_from_id(bpf_args.cgroup_id, &cm) != 0)
		return 0;

	if (bpf_try_to_free_mem_cgroup_pages(cm.memcg, 32, GFP_KERNEL,
					     0, -1) > 0) {
		if (bpf_mem_cgroup_usage(cm.memcg) >=
		    bpf_args.limit_bytes - (ONE_MB_PAGE_COUNT * __PAGE_SIZE)) {
			__u32 key2 = 0;
			struct wq_elem *elem;

			elem = bpf_map_lookup_elem(&wq_map, &key2);
			if (elem) {
				bpf_wq_start(&elem->work, 0);
				started_wq = true;
			}
		}
	}
	if (!started_wq)
		__atomic_exchange_n(&async_free_run, 0, __ATOMIC_RELEASE);

	put_cgroup_memcg(&cm);
	return 0;
}

SEC("syscall")
int prog_init(struct bpf_args_s *ctx)
{
	struct wq_elem *elem;
	__u32 key = 0;
	int ret;
	u64 expected = 1;

	if (!__atomic_compare_exchange_n(&initialize_status,
					 &expected, 2,
					 false,
					 __ATOMIC_ACQ_REL,
					 __ATOMIC_RELAXED))
		return -1;

	elem = bpf_map_lookup_elem(&wq_map, &key);
	if (!elem)
		return -1;
	ret = bpf_wq_init(&elem->work, &wq_map, 0);
	if (ret)
		goto out;
	ret = bpf_wq_set_callback(&elem->work, async_free, 0);
	if (ret)
		goto out;

	allocated = 0;
	async_free_run = 0;
	bpf_args.cgroup_id = ctx->cgroup_id;
	bpf_args.limit_bytes = ctx->limit_bytes;

out:
	return ret;
}

static u64 get_usage(void)
{
	u64 ret = 0;
	struct cgroup_memcg cm;

	if (get_cgroup_memcg_from_id(bpf_args.cgroup_id, &cm) != 0)
		return 0;

	ret = bpf_mem_cgroup_usage(cm.memcg);

	put_cgroup_memcg(&cm);

	return ret;
}

s64 abs_diff(s64 a, s64 b)
{
	return a > b ? a - b : b - a;
}

SEC("struct_ops/memcg_charged")
unsigned int BPF_PROG(memcg_charged_impl, struct mem_cgroup *memcg,
		      unsigned int nr_pages)
{
	struct wq_elem *elem;
	__u32 key = 0;
	u64 expected = 0;
	s64 cur_allocated;
	s64 cur_old_allocated;

	__atomic_add_fetch(&allocated, nr_pages, __ATOMIC_RELAXED);
	cur_allocated = READ_ONCE(allocated);
	cur_old_allocated = READ_ONCE(old_allocated);
	if (abs_diff(cur_allocated, cur_old_allocated) < ONE_MB_PAGE_COUNT)
		goto out;
	WRITE_ONCE(old_allocated, cur_allocated);

	if (get_usage() < bpf_args.limit_bytes)
		goto out;

	if (__atomic_compare_exchange_n(&async_free_run,
					&expected, 1,
					false,
					__ATOMIC_ACQ_REL,
					__ATOMIC_RELAXED)) {
		elem = bpf_map_lookup_elem(&wq_map, &key);
		if (!elem)
			return 0;

		bpf_wq_start(&elem->work, 0);
	}

out:
	return 0;
}

SEC("struct_ops/memcg_uncharged")
void BPF_PROG(memcg_uncharged_impl, struct mem_cgroup *memcg,
	      unsigned int nr_pages)
{
	__atomic_sub_fetch(&allocated, nr_pages, __ATOMIC_RELAXED);
}

SEC(".struct_ops.link")
struct memcg_bpf_ops mcg_ops = {
	.memcg_charged = (void *)memcg_charged_impl,
	.memcg_uncharged = (void *)memcg_uncharged_impl,
};

char LICENSE[] SEC("license") = "GPL";
