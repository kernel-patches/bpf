// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_misc.h"
#include "bpf_experimental.h"

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
__description("file_kptr: xchg and reinsert")
__success
int xchg_reinsert_file_kptr(struct file *ctx_file)
{
	struct file_map_value *mapval;
	struct file *file, *old;
	int zero = 0;

	(void)ctx_file;

	mapval = bpf_map_lookup_elem(&stashed_files, &zero);
	if (!mapval)
		return 0;

	file = bpf_get_task_exe_file(bpf_get_current_task_btf());
	if (!file)
		return 0;

	old = bpf_kptr_xchg(&mapval->file, file);
	if (old)
		bpf_put_file(old);

	file = bpf_kptr_xchg(&mapval->file, NULL);
	if (!file)
		return 0;

	old = bpf_kptr_xchg(&mapval->file, file);
	if (old) {
		bpf_put_file(old);
		return 0;
	}

	file = bpf_kptr_xchg(&mapval->file, NULL);
	if (file)
		bpf_put_file(file);

	return 0;
}

char _license[] SEC("license") = "GPL";
