// SPDX-License-Identifier: GPL-2.0
/* Copyright © 2026 Justin Suess <utilityemal77@gmail.com> */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct bpf_landlock_ruleset;

extern struct bpf_landlock_ruleset *
bpf_landlock_get_ruleset_from_fd(int fd) __ksym;
extern void
bpf_landlock_put_ruleset(struct bpf_landlock_ruleset *ruleset) __ksym;
extern int bpf_landlock_restrict_binprm(struct linux_binprm *bprm,
					struct bpf_landlock_ruleset *ruleset,
					u32 flags) __ksym;

/* The LSM policy kfuncs are limited to LSM and syscall programs by
 * the BPF-side kfunc filter: a tracing program calling one must fail
 * verification.
 */
SEC("tp_btf/task_newtask")
__failure __msg("calling kernel function bpf_landlock_get_ruleset_from_fd is not allowed")
int BPF_PROG(tracing_prog, struct task_struct *task, u64 clone_flags)
{
	struct bpf_landlock_ruleset *ruleset;

	ruleset = bpf_landlock_get_ruleset_from_fd(-1);
	if (ruleset)
		bpf_landlock_put_ruleset(ruleset);
	return 0;
}

/* A ruleset fd is only meaningful in the fd table of the task that
 * set the ruleset up: the acquire kfunc is exclusive to syscall
 * programs and must be rejected in an LSM program, even on an
 * allowed hook.
 */
SEC("lsm.s/bprm_creds_for_exec")
__failure __msg("calling kernel function bpf_landlock_get_ruleset_from_fd is not allowed")
int BPF_PROG(lsm_get, struct linux_binprm *bprm)
{
	struct bpf_landlock_ruleset *ruleset;

	ruleset = bpf_landlock_get_ruleset_from_fd(-1);
	if (ruleset)
		bpf_landlock_put_ruleset(ruleset);
	return 0;
}

/* Enforcement needs an execution to restrict: the enforcement kfunc
 * is exclusive to the sleepable bprm LSM hooks and must be rejected
 * in a syscall program.
 */
SEC("syscall")
__failure __msg("calling kernel function bpf_landlock_restrict_binprm is not allowed")
int syscall_restrict(void *ctx)
{
	return bpf_landlock_restrict_binprm(NULL, NULL, 0);
}

/* Any LSM attach point other than the sleepable bprm hooks must be
 * rejected.
 */
SEC("lsm.s/file_open")
__failure __msg("calling kernel function bpf_landlock_put_ruleset is not allowed")
int BPF_PROG(wrong_hook, struct file *file)
{
	bpf_landlock_put_ruleset(NULL);
	return 0;
}

/* The kfuncs may sleep: a non-sleepable program on an allowed hook
 * must be rejected.
 */
SEC("lsm/bprm_creds_for_exec")
__failure
__msg("program must be sleepable to call sleepable kfunc bpf_landlock_put_ruleset")
int BPF_PROG(nonsleepable_prog, struct linux_binprm *bprm)
{
	bpf_landlock_put_ruleset(NULL);
	return 0;
}

/* An acquired ruleset reference must be released before returning. */
SEC("syscall")
__failure __msg("Unreleased reference")
int leak_ruleset(void *ctx)
{
	bpf_landlock_get_ruleset_from_fd(-1);
	return 0;
}
