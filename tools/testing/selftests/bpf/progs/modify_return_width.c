// SPDX-License-Identifier: GPL-2.0
/* See serial_test_modify_return_width() */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

int pid;
__u64 value;			/* The fmod_ret programs return it */
__u64 int_ret, bool_ret;	/* The fexit programs read it */

SEC("fmod_ret/bpf_modify_return_test")
long BPF_PROG(mod_int, int a, int *b, int ret)
{
	return bpf_get_current_pid_tgid() >> 32 == pid ? value : 0;
}

SEC("fexit/bpf_modify_return_test")
int BPF_PROG(exit_int, int a, int *b, int ret)
{
	if (bpf_get_current_pid_tgid() >> 32 == pid)
		bpf_get_func_ret(ctx, &int_ret);
	return 0;
}

SEC("fmod_ret/bpf_testmod_modify_return_bool")
long BPF_PROG(mod_bool, bool ret)
{
	return bpf_get_current_pid_tgid() >> 32 == pid ? value : 0;
}

SEC("fexit/bpf_testmod_modify_return_bool")
int BPF_PROG(exit_bool, bool ret)
{
	if (bpf_get_current_pid_tgid() >> 32 == pid)
		bpf_get_func_ret(ctx, &bool_ret);
	return 0;
}
