/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2017 Facebook
 */
#ifndef __MAP_IN_MAP_H__
#define __MAP_IN_MAP_H__

#include <linux/types.h>

struct file;
struct bpf_map;

struct bpf_inner_map_element {
	/* map must be the first member, array_of_map_gen_lookup() and
	 * htab_of_map_lookup_elem() depend on it to dereference map correctly.
	 */
	struct bpf_map *map;
	struct rcu_head rcu;
};

struct bpf_map *bpf_map_meta_alloc(int inner_map_ufd);
void bpf_map_meta_free(struct bpf_map *map_meta);
void *bpf_map_fd_get_ptr(struct bpf_map *map, struct file *map_file, int ufd);
void bpf_map_fd_put_ptr(void *ptr, bool need_defer);
u32 bpf_map_fd_sys_lookup_elem(void *ptr);

void *bpf_map_of_map_fd_get_ptr(struct bpf_map *map, struct file *map_file, int ufd);
void bpf_map_of_map_fd_put_ptr(void *ptr, bool need_defer);
u32 bpf_map_of_map_fd_sys_lookup_elem(void *ptr);

#endif
