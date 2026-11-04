// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ENOENT 2

char _license[] SEC("license") = "GPL";

/* Opening this map fails as if it had been freed. */
__u32 hidden_id;

SEC("fmod_ret/security_bpf_map")
int BPF_PROG(hide_map, struct bpf_map *map, int fmode)
{
	return map->id == hidden_id ? -ENOENT : 0;
}
