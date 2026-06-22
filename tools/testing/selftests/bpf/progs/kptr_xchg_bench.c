// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2026. Loongson Technology Corporation Limited */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "bpf_experimental.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

#define MAX_XCHG_LOOPS 4096

struct bin_data {
	char blob[32];
};

#define private(name) SEC(".bss." #name) __hidden __attribute__((aligned(8)))

private(kptr) struct bin_data __kptr *ptr;
u32 nr_loops = 256;
long hits;

SEC("fentry/" SYS_PREFIX "sys_getpgid")
int benchmark(void *ctx)
{
	struct bin_data *old;
	u32 i;

	for (i = 0; i < MAX_XCHG_LOOPS; i++) {
		if (i >= nr_loops)
			break;

		old = bpf_kptr_xchg(&ptr, NULL);
		if (old)
			bpf_obj_drop(old);
	}

	__sync_add_and_fetch(&hits, i);
	return 0;
}

/*
 * BTF FUNC records are not generated for kfuncs referenced only through
 * optimized paths. Keep bpf_obj_drop() visible to libbpf's kfunc linker.
 */
void __btf_root(void)
{
	bpf_obj_drop(NULL);
}
