// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include "err.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/string.h>

char _license[] SEC("license") = "GPL";

int pid;

u32 build_id_bin_size;
u32 build_id_lib_size;

char build_id_bin[BUILD_ID_SIZE_MAX];
char build_id_lib[BUILD_ID_SIZE_MAX];

long build_id_bin_err;
long build_id_lib_err;

static int store_build_id(struct file *file, char *build_id, u32 *sz, long *err)
{
	struct build_id *bid;

	bid = file->f_build_id;
	if (IS_ERR_OR_NULL(bid)) {
		*err = PTR_ERR(bid);
		return 0;
	}
	*sz = bid->sz;
	if (bid->sz > sizeof(bid->data)) {
		*err = 1;
		return 0;
	}
	__builtin_memcpy(build_id, bid->data, sizeof(bid->data));
	*err = 0;
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(prog, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	int cur_pid = bpf_get_current_pid_tgid() >> 32;

	if (pid != cur_pid)
		return 0;
	if (!bprm->file)
		return 0;
	return store_build_id(bprm->file, build_id_bin, &build_id_bin_size, &build_id_bin_err);
}

static long check_vma(struct task_struct *task, struct vm_area_struct *vma,
		      void *data)
{
	if (!vma || !vma->vm_file || !vma->vm_file)
		return 0;
	return store_build_id(vma->vm_file, build_id_lib, &build_id_lib_size, &build_id_lib_err);
}

SEC("uprobe/./liburandom_read.so:urandlib_read_without_sema")
int BPF_UPROBE(urandlib_read_without_sema)
{
	struct task_struct *task = bpf_get_current_task_btf();
	int cur_pid = bpf_get_current_pid_tgid() >> 32;

	if (pid != cur_pid)
		return 0;
	return bpf_find_vma(task, ctx->ip, check_vma, NULL, 0);
}
