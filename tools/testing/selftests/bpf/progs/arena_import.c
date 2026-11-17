// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 NVIDIA Corporation */

#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf_arena_common.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 9); /* number of pages, page 0 is left unused */
} arena SEC(".maps");

int bpf_arena_import_memfd(void *map, void __arena *addr, __u32 page_cnt,
			   int fd, __u64 off) __ksym;
int bpf_arena_import_dax(void *map, void __arena *addr, __u32 page_cnt,
			 __u64 src) __ksym;

char __arena *base;	/* in:  user address of the arena */
__u64 page_size;	/* in:  page size */
__u32 pg;		/* in:  arena page index */
__u32 page_cnt;		/* in:  number of pages */
int fd;			/* in:  memfd to import */
__u64 fd_off;		/* in:  byte offset in the memfd */
__u64 src;		/* in:  user address of the pages to import by address */
__u64 val;		/* in/out: value written/read at the start of page pg */
int ret;		/* out: result of the last operation */

#ifdef __BPF_FEATURE_ADDR_SPACE_CAST
const volatile bool skip = false;
#define ARENA_OP(stmt)	stmt

/*
 * Page pg of the tests is arena page pg + 1. Arena page 0 is left unused: its
 * address is NULL to the kfuncs when the arena starts on a 4GB boundary.
 */
static __always_inline char __arena *page_addr(void)
{
	/* Programs that only dereference arena pointers must still use the map */
	asm volatile("" :: "r"(&arena));
	return base + (pg + 1) * page_size;
}
#else
/* Arena pointers need the compiler's address space casts, the tests skip */
const volatile bool skip = true;
#define ARENA_OP(stmt)
#endif

SEC("syscall")
int op_import(void *ctx)
{
	ARENA_OP(ret = bpf_arena_import_memfd(&arena, page_addr(), page_cnt, fd, fd_off));
	return 0;
}

SEC("syscall")
int op_import_dax(void *ctx)
{
	ARENA_OP(ret = bpf_arena_import_dax(&arena, page_addr(), page_cnt, src));
	return 0;
}

SEC("syscall")
int op_alloc(void *ctx)
{
	ARENA_OP(ret = bpf_arena_alloc_pages(&arena, page_addr(), page_cnt, NUMA_NO_NODE, 0) ?
		       0 : -1);
	return 0;
}

SEC("syscall")
int op_free(void *ctx)
{
	ARENA_OP(bpf_arena_free_pages(&arena, page_addr(), page_cnt));
	return 0;
}

SEC("syscall")
int op_write(void *ctx)
{
	ARENA_OP(*(__u64 __arena *)page_addr() = val);
	return 0;
}

SEC("syscall")
int op_read(void *ctx)
{
	ARENA_OP(val = *(__u64 __arena *)page_addr());
	return 0;
}

char _license[] SEC("license") = "GPL";
