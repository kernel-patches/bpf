// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

static const char expected_args[] = "bpf-copy-bprm\0deny";
static const char expected_arg0[] = "bpf-copy-bprm";
static const char expected_arg1[] = "deny";

int monitored_pid;
int invalid_flags_ret;
int copy_ret;
int str_arg0_ret;
int str_arg1_ret;
int hook_calls;
bool args_match;
bool str_args_match;

extern int bpf_copy_from_user_bprm(void *dst, u32 dst__sz,
					   const void *unsafe_ptr__ign,
					   const struct linux_binprm *bprm,
					   u64 flags) __ksym;

extern int bpf_copy_from_user_bprm_str(void *dst, u32 dst__sz,
					       const void *unsafe_ptr__ign,
					       const struct linux_binprm *bprm,
					       u64 flags) __ksym;

SEC("lsm.s/bprm_check_security")
int BPF_PROG(check_exec_args, struct linux_binprm *bprm, int ret)
{
	char args[sizeof(expected_args)];
	char arg0[32];
	char arg1[32];
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	int arg0_ret;
	int arg1_ret;
	u32 i;

	if (ret || pid != monitored_pid)
		return ret;

	hook_calls++;
	invalid_flags_ret = bpf_copy_from_user_bprm(args, sizeof(args),
						       (void *)bprm->p, bprm, 1);
	copy_ret = bpf_copy_from_user_bprm(args, sizeof(args),
						     (void *)bprm->p, bprm, 0);
	if (copy_ret)
		return 0;

	args_match = true;
	for (i = 0; i < sizeof(expected_args); i++) {
		if (args[i] != expected_args[i]) {
			args_match = false;
			break;
		}
	}

	arg0_ret = bpf_copy_from_user_bprm_str(arg0, sizeof(arg0),
						(void *)bprm->p, bprm,
						BPF_F_PAD_ZEROS);
	str_arg0_ret = arg0_ret;
	if (arg0_ret != sizeof(expected_arg0))
		return 0;

	arg1_ret = bpf_copy_from_user_bprm_str(arg1, sizeof(arg1),
						(void *)(bprm->p + arg0_ret),
						bprm, BPF_F_PAD_ZEROS);
	str_arg1_ret = arg1_ret;
	if (arg1_ret != sizeof(expected_arg1))
		return 0;

	str_args_match = true;
	for (i = 0; i < sizeof(arg0); i++) {
		if (arg0[i] != (i < sizeof(expected_arg0) ? expected_arg0[i] : 0) ||
		    arg1[i] != (i < sizeof(expected_arg1) ? expected_arg1[i] : 0)) {
			str_args_match = false;
			break;
		}
	}

	return args_match && str_args_match ? -EPERM : 0;
}
