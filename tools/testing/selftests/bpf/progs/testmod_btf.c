// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

int bpf_testmod_put = 0;

SEC("kprobe/btf_put")
int BPF_KPROBE(kprobe_btf_put, struct btf *btf)
{
	const char name[] = "bpf_testmod";
	int i;

	for (i = 0; i < sizeof(name); i++) {
		if (BPF_CORE_READ(btf, name[i]) != name[i])
			return 0;
	}

	if (BPF_CORE_READ(btf, refcnt.refs.counter) == 1)
		bpf_testmod_put = 1;

	return 0;
}
