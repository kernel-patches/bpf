// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define FILENAME_MAX_SIZE 256
#define TARGET_DIR "/tmp/"
#define TARGET_DIR_LEN 5

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} result SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(d_path_lsm_prog, struct linux_binprm *bprm)
{
	char path[FILENAME_MAX_SIZE] = {};
	long len;
	int key = 0;
	int val = 0;

	len = bpf_d_path(&bprm->file->f_path, path, sizeof(path));
	if (len < 0)
		return 0;

#pragma unroll
	for (int i = 0; i < TARGET_DIR_LEN; i++) {
		if ((u8)path[i] != (u8)TARGET_DIR[i]) {
			val = -1; /* mismatch */
			bpf_map_update_elem(&result, &key, &val, BPF_ANY);
			return 0;
		}
	}

	val = 1; /* prefix match */
	bpf_map_update_elem(&result, &key, &val, BPF_ANY);
	return 0;
}
