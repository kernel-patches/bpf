// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

static const char expected_data[] = "first\0second-argument\0"
				    "SOME_ENV=a\0OTHER_ENV=something";
static const char expected_arg0[] = "first";
static const char expected_arg1[] = "second-argument";
static const char expected_env0[] = "SOME_ENV=a";
static const char expected_env1[] = "OTHER_ENV=something";

int monitored_pid;
int bprm_argc;
int bprm_envc;
int data_len_match;
int invalid_flags_ret;
int copy_ret;
int str_arg0_ret;
int str_arg1_ret;
int str_env0_ret;
int str_env1_ret;
int data_match;
int str_args_match;
int str_envs_match;

extern bool CONFIG_MMU __kconfig __weak;

extern int bpf_copy_from_user_mm(void *dst, u32 dst__sz,
				 const void *unsafe_ptr__ign,
				 struct mm_struct *mm, u64 flags) __ksym;

extern int bpf_copy_from_user_mm_str(void *dst, u32 dst__sz,
				     const void *unsafe_ptr__ign,
				     struct mm_struct *mm, u64 flags) __ksym;

SEC("lsm.s/bprm_check_security")
int BPF_PROG(check_exec_args, struct linux_binprm *bprm)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	char data[sizeof(expected_data)];
	struct mm_struct *mm;
	char arg0[32];
	char arg1[32];
	char env0[32];
	char env1[32];
	u64 offset = 0;
	u64 data_len;

	if (!CONFIG_MMU)
		return 0;

	if (pid != monitored_pid)
		return 0;

	mm = bprm->mm;
	if (!mm)
		return 0;

	bprm_argc = bprm->argc;
	bprm_envc = bprm->envc;

	/* this is the total size of args and envs starting from bprm->p */
	data_len = bprm->exec - bprm->p;
	data_len_match = data_len == sizeof(expected_data);

	invalid_flags_ret = bpf_copy_from_user_mm(data,
						  sizeof(data), (void *)bprm->p, mm, ~0ULL);

	copy_ret = bpf_copy_from_user_mm(data, sizeof(data), (void *)bprm->p,
					 mm, 0);
	if (copy_ret)
		return 0;

	data_match =
		!__builtin_memcmp(data, expected_data, sizeof(expected_data));

	/* arg0 is at bprm->p */
	str_arg0_ret = bpf_copy_from_user_mm_str(arg0, sizeof(arg0),
						 (void *)(bprm->p + offset),
						 mm, BPF_F_PAD_ZEROS);
	if (str_arg0_ret != sizeof(expected_arg0))
		return 0;
	offset += str_arg0_ret;

	/* arg1 is at bprm->p + sizeof(arg0) */
	str_arg1_ret = bpf_copy_from_user_mm_str(arg1, sizeof(arg1),
						 (void *)(bprm->p + offset),
						 mm, BPF_F_PAD_ZEROS);
	if (str_arg1_ret != sizeof(expected_arg1))
		return 0;
	offset += str_arg1_ret;

	/* env0 is at bprm->p + sizeof(arg0) + sizeof(arg1) */
	str_env0_ret = bpf_copy_from_user_mm_str(env0, sizeof(env0),
						 (void *)(bprm->p + offset),
						 mm, BPF_F_PAD_ZEROS);
	if (str_env0_ret != sizeof(expected_env0))
		return 0;
	offset += str_env0_ret;

	/* env1 is at bprm->p + sizeof(arg0) + sizeof(arg1) + sizeof(env0) */
	str_env1_ret = bpf_copy_from_user_mm_str(env1, sizeof(env1),
						 (void *)(bprm->p + offset),
						 mm, BPF_F_PAD_ZEROS);
	if (str_env1_ret != sizeof(expected_env1))
		return 0;

	str_args_match =
		!__builtin_memcmp(arg0, expected_arg0, sizeof(expected_arg0)) &&
		!__builtin_memcmp(arg1, expected_arg1, sizeof(expected_arg1));
	str_envs_match =
		!__builtin_memcmp(env0, expected_env0, sizeof(expected_env0)) &&
		!__builtin_memcmp(env1, expected_env1, sizeof(expected_env1));

	return data_match && str_args_match && str_envs_match ? -EPERM : 0;
}
