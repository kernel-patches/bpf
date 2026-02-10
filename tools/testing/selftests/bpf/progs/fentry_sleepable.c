// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

int copy_test = 0;

SEC("fentry.s/" SYS_PREFIX "sys_setdomainname")
int BPF_PROG(test_sys_setdomainname, struct pt_regs *regs)
{
	void *ptr = (void *)PT_REGS_PARM1_SYSCALL(regs);
	int len = PT_REGS_PARM2_SYSCALL(regs);
	int buf = 0;
	long ret;

	ret = bpf_copy_from_user(&buf, sizeof(buf), ptr);
	if (len == -2 && ret == 0 && buf == 1234)
		copy_test++;
	if (len == -3 && ret == -EFAULT)
		copy_test++;
	if (len == -4 && ret == -EFAULT)
		copy_test++;
	return 0;
}
