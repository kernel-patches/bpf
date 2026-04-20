// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

struct file_map_value {
	struct file __kptr * file;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct file_map_value);
	__uint(max_entries, 1);
} stashed_files SEC(".maps");

SEC("lsm.s/file_open")
__failure __msg("R2 type=ctx expected=ptr_, trusted_ptr_, rcu_ptr_")
int stash_unref_ctx_file(struct file *ctx_file)
{
	struct file_map_value *mapval;
	int zero = 0;

	mapval = bpf_map_lookup_elem(&stashed_files, &zero);
	if (!mapval)
		return 0;

	/* ctx_file is just the hook argument, not an acquired file reference. */
	bpf_kptr_xchg(&mapval->file, ctx_file);
	return 0;
}

char _license[] SEC("license") = "GPL";
