// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

#define PF_EXITING 0x00000004

char _license[] SEC("license") = "GPL";

__u64 monitored_ino;
int called;
int ret;

/*
 * A task that exits with a file still open releases it from
 * exit_task_work(), after exit_fs() has already cleared its fs.
 */
SEC("lsm/file_release")
int BPF_PROG(path_d_path_on_exit, struct file *file)
{
	struct task_struct *task = bpf_get_current_task_btf();
	char buf[64];

	if (file->f_inode->i_ino != monitored_ino ||
	    !(task->flags & PF_EXITING))
		return 0;

	ret = bpf_path_d_path(&file->f_path, buf, sizeof(buf));
	called = 1;
	return 0;
}
