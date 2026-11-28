// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RHASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 128);
	__type(key, int);
	__type(value, long);
} rhmap SEC(".maps");

int hits;
int busy;

/* The resize worker calls this with the key's bucket lock held */
SEC("kprobe/rhashtable_jhash2")
int BPF_KPROBE(rhash_resize_delete, const void *key, u32 length)
{
	int k;

	if (length != 1 || bpf_probe_read_kernel(&k, sizeof(k), key) || k != 7)
		return 0;

	__sync_fetch_and_add(&hits, 1);
	if (bpf_map_delete_elem(&rhmap, &k) == -EBUSY)
		__sync_fetch_and_add(&busy, 1);
	return 0;
}
