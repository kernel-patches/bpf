/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Subset of bpf.h declarations, split out so files that need only these
 * declarations can avoid bpf.h's full include cost.
 */
#ifndef _LINUX_BPF_DEFS_H
#define _LINUX_BPF_DEFS_H

#include <linux/types.h>

struct slab;

#ifdef CONFIG_BPF_SYSCALL
bool bpf_arena_handle_page_fault(unsigned long addr, bool is_write, unsigned long fault_ip);
struct slab *bpf_arena_alloc_slab_page(void *arena, gfp_t flags, int node,
				       bool allow_spin);
void bpf_arena_free_slab_page(void *arena, struct slab *slab);
#else
static inline bool bpf_arena_handle_page_fault(unsigned long addr, bool is_write,
					       unsigned long fault_ip)
{
	return false;
}
static inline struct slab *bpf_arena_alloc_slab_page(void *arena, gfp_t flags,
						     int node, bool allow_spin)
{
	return NULL;
}
static inline void bpf_arena_free_slab_page(void *arena, struct slab *slab) { }
#endif

#endif /* _LINUX_BPF_DEFS_H */
