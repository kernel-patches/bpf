// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

int pid = 0;

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
	struct task_struct *current = bpf_get_current_task_btf();
	unsigned long *val, l;
	char buf[64] = {};
	struct file *f;

	if (current->tgid != pid)
		return 0;

	f = current->files->fd_array[63];
	bpf_d_path(&f->f_path, buf, sizeof(buf));
	/* If we survived, let's try our luck here */
	bpf_sock_from_file(f);
	return 0;
}

char _license[] SEC("license") = "GPL";
