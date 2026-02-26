/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Cloudflare, Inc. */

#ifndef _BPF_SKB_STORAGE_H
#define _BPF_SKB_STORAGE_H

#ifdef CONFIG_BPF_SKB_STORAGE

#include <linux/compiler_types.h>

struct bpf_local_storage;

struct bpf_skb_storage_ext {
	struct bpf_local_storage __rcu *storage;
};

void bpf_skb_storage_free(struct bpf_skb_storage_ext *ext);

#endif /* CONFIG_BPF_SKB_STORAGE */

#endif /* _BPF_SKB_STORAGE_H */
