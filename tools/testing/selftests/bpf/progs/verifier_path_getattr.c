// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_kfuncs.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

static struct bpf_file_stat output;

SEC("lsm.s/file_open")
__success
int BPF_PROG(getattr_embedded_path_stack, struct file *file)
{
	struct bpf_file_stat st;

	bpf_path_getattr(&file->f_path, 0, 0, &st, sizeof(st));
	return 0;
}

SEC("lsm.s/file_open")
__failure __msg("dereference of modified untrusted_ptr_")
int BPF_PROG(getattr_untrusted_path)
{
	struct task_struct *task = bpf_get_current_task_btf();

	bpf_path_getattr(&task->fs->pwd, 0, 0, &output, sizeof(output));
	return 0;
}

SEC("lsm/inode_getattr")
__failure __msg("program must be sleepable to call sleepable kfunc bpf_path_getattr")
int BPF_PROG(getattr_non_sleepable, const struct path *path)
{
	bpf_path_getattr(path, 0, 0, &output, sizeof(output));
	return 0;
}

SEC("fentry/vfs_getattr")
__failure __msg("calling kernel function bpf_path_getattr is not allowed")
int BPF_PROG(getattr_fentry, const struct path *path)
{
	bpf_path_getattr(path, 0, 0, &output, sizeof(output));
	return 0;
}

SEC("lsm.s/inode_getattr")
__failure __msg("invalid write to stack")
int BPF_PROG(getattr_short_output, const struct path *path)
{
	__u64 small;

	bpf_path_getattr(path, 0, 0, (void *)&small, sizeof(output));
	return 0;
}
