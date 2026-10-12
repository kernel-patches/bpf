/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 */
#ifndef ARENA_KVM_SHARED_H
#define ARENA_KVM_SHARED_H

/* These flags may be absent from a pre-series kernel's vmlinux.h. */
#ifndef BPF_F_ARENA_NO_FREE
#define BPF_F_ARENA_NO_FREE (1U << 20)
#endif
#ifndef BPF_F_ARENA_EXPORT
#define BPF_F_ARENA_EXPORT (1U << 21)
#endif

struct arena_kvm_features {
	unsigned int addr_space_cast;
};

#ifdef __BPF__
#ifdef __BPF_FEATURE_ADDR_SPACE_CAST
const volatile struct arena_kvm_features features = { .addr_space_cast = 1 };
#else
const volatile struct arena_kvm_features features = {};
#endif
#else
/* Inspect compiler support before loading maps or booting either guest. */
static inline int arena_kvm_check_features(struct bpf_object *obj)
{
	const struct arena_kvm_features *features;
	struct bpf_map *map;
	size_t size;

	map = bpf_object__find_map_by_name(obj, ".rodata");
	if (!map)
		return 1;
	features = bpf_map__initial_value(map, &size);
	if (!features || size != sizeof(*features))
		return 1;
	return features->addr_space_cast ? 0 : 4; /* KSFT_SKIP */
}
#endif

#define ARENA_KVM_NODE 1

#define GUEST_READY 0x4152454e414b564dULL
#define HOST_FIRST 0x123456789abcdef0ULL
#define GUEST_FIRST 0xfedcba9876543210ULL
#define HOST_SECOND 0x1020304050607080ULL
#define GUEST_SECOND 0x8070605040302010ULL

struct signal_page {
	volatile unsigned long long ready;
	volatile unsigned long long h2g_payload;
	volatile unsigned long long h2g_seq;
	volatile unsigned long long g2h_payload;
	volatile unsigned long long g2h_seq;
};

#endif
