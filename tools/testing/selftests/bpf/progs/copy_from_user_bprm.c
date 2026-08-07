// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

static const char expected_args[] = "first\0second-argument";
static const char expected_arg0[] = "first";
static const char expected_arg1[] = "second-argument";

int monitored_pid;
int bprm_argc;
int invalid_flags_ret;
int copy_ret;
int str_arg0_ret;
int str_arg1_ret;
int args_match;
int str_args_match;

extern int bpf_copy_from_user_mm(void *dst, u32 dst__sz,
				const void *unsafe_ptr__ign,
				struct mm_struct *mm, u64 flags) __ksym;

extern int bpf_copy_from_user_mm_str(void *dst, u32 dst__sz,
				    const void *unsafe_ptr__ign,
				    struct mm_struct *mm, u64 flags) __ksym;

SEC("lsm.s/bprm_check_security")
int BPF_PROG(check_exec_args, struct linux_binprm *bprm, int ret)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct mm_struct *mm;
	char args[sizeof(expected_args)];
	char arg0[32];
	char arg1[32];

	if (ret || pid != monitored_pid)
		return ret;

	mm = bprm->mm;
	if (!mm)
		return 0;

	bprm_argc = bprm->argc;

	invalid_flags_ret = bpf_copy_from_user_mm(args, sizeof(args),
						  (void *)bprm->p, mm, 1);

	copy_ret = bpf_copy_from_user_mm(args, sizeof(args),
					 (void *)bprm->p, mm, 0);
	if (copy_ret)
		return 0;

	args_match = !__builtin_memcmp(args, expected_args, sizeof(expected_args));

	str_arg0_ret = bpf_copy_from_user_mm_str(arg0, sizeof(arg0),
						 (void *)bprm->p, mm,
						 BPF_F_PAD_ZEROS);
	if (str_arg0_ret != sizeof(expected_arg0))
		return 0;

	str_arg1_ret = bpf_copy_from_user_mm_str(arg1, sizeof(arg1),
						 (void *)(bprm->p + str_arg0_ret),
						 mm, BPF_F_PAD_ZEROS);
	if (str_arg1_ret != sizeof(expected_arg1))
		return 0;

	str_args_match = !__builtin_memcmp(arg0, expected_arg0, sizeof(expected_arg0)) &&
			!__builtin_memcmp(arg1, expected_arg1, sizeof(expected_arg1));

	return args_match && str_args_match ? -EPERM : 0;
}
