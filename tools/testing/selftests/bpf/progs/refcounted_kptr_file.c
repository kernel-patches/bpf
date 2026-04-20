// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_kfuncs.h"
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

static const char xattr_name[] = "user.kptr_ref";
static const char expected_value[] = "kptr-live";

char file_kptr_probe_value[32];
int file_kptr_insert_pid;
int file_kptr_verify_pid;
int file_kptr_inserted;
int file_kptr_verified;
int file_kptr_err;
int file_kptr_xattr_ret;
char file_kptr_value[32];

SEC("lsm.s/file_open")
int insert_file_kptr(struct file *ctx_file)
{
	struct bpf_dynptr value_ptr;
	struct file_map_value *mapval;
	struct task_struct *task;
	struct file *file, *old;
	int ret;
	int zero = 0;

	(void)ctx_file;

	if ((__u32)(bpf_get_current_pid_tgid() >> 32) != (__u32)file_kptr_insert_pid)
		return 0;

	if (file_kptr_inserted)
		return 0;

	mapval = bpf_map_lookup_elem(&stashed_files, &zero);
	if (!mapval) {
		file_kptr_err = 1;
		return 0;
	}

	task = bpf_get_current_task_btf();
	file = bpf_get_task_exe_file(task);
	if (!file) {
		file_kptr_err = 2;
		return 0;
	}

	/* Exec can open multiple files while the new image is being installed.
	 * Only stash the child's final executable, which we identify by the test
	 * xattr.
	 */
	ret = bpf_dynptr_from_mem(file_kptr_probe_value,
				  sizeof(file_kptr_probe_value), 0,
				  &value_ptr);
	if (ret) {
		file_kptr_err = 8;
		bpf_put_file(file);
		return 0;
	}

	ret = bpf_get_file_xattr(file, xattr_name, &value_ptr);
	if (ret != sizeof(expected_value) ||
	    bpf_strncmp(file_kptr_probe_value, sizeof(expected_value),
			expected_value)) {
		bpf_put_file(file);
		return 0;
	}

	old = bpf_kptr_xchg(&mapval->file, file);
	if (old)
		bpf_put_file(old);

	file_kptr_inserted = 1;
	return 0;
}

SEC("lsm.s/file_open")
int verify_file_kptr(struct file *ctx_file)
{
	struct bpf_dynptr value_ptr;
	struct file_map_value *mapval;
	struct file *file;
	int zero = 0;
	int ret;

	(void)ctx_file;

	if ((__u32)(bpf_get_current_pid_tgid() >> 32) != (__u32)file_kptr_verify_pid)
		return 0;

	if (!file_kptr_inserted || file_kptr_verified)
		return 0;

	mapval = bpf_map_lookup_elem(&stashed_files, &zero);
	if (!mapval) {
		file_kptr_err = 3;
		return 0;
	}

	/* 
	 * Pull the file out of the map to get a referenced pointer for the xattr
	 * kfunc and to drop the map's last reference once verification completes.
	 */
	file = bpf_kptr_xchg(&mapval->file, NULL);
	if (!file) {
		file_kptr_err = 4;
		return 0;
	}

	ret = bpf_dynptr_from_mem(file_kptr_value, sizeof(file_kptr_value), 0,
				  &value_ptr);
	if (ret) {
		file_kptr_err = 5;
		bpf_put_file(file);
		return 0;
	}

	ret = bpf_get_file_xattr(file, xattr_name, &value_ptr);
	file_kptr_xattr_ret = ret;
	if (ret != sizeof(expected_value)) {
		file_kptr_err = 6;
		bpf_put_file(file);
		return 0;
	}

	if (bpf_strncmp(file_kptr_value, sizeof(expected_value), expected_value)) {
		file_kptr_err = 7;
		bpf_put_file(file);
		return 0;
	}

	file_kptr_verified = 1;
	bpf_put_file(file);
	return 0;
}

char _license[] SEC("license") = "GPL";
