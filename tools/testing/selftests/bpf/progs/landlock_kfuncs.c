// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_kfuncs.h"

u32 target_pid;
bool enable_bprm_creds_for_exec;
bool enable_bprm_creds_from_file;
u32 restrict_flags;

int matched_pid;
int bprm_creds_for_exec_hits;
int bprm_creds_from_file_hits;
int lookup_calls;
int lookup_failed;
int restrict_calls;
int restrict_ret;
int put_calls;

struct {
	__uint(type, BPF_MAP_TYPE_LANDLOCK_RULESET);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} ruleset_map SEC(".maps");

char _license[] SEC("license") = "GPL";

static __always_inline bool is_target_exec(void)
{
	u32 pid;

	if (!target_pid)
		return false;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != target_pid)
		return false;

	matched_pid = 1;
	return true;
}

static __always_inline int apply_landlock_ruleset(struct linux_binprm *bprm,
						  int *hook_hits)
{
	const struct bpf_landlock_ruleset *ruleset;
	__u32 key = 0;

	if (!is_target_exec())
		return 0;

	(*hook_hits)++;

	lookup_calls++;
	ruleset = bpf_map_lookup_elem(&ruleset_map, &key);
	if (!ruleset) {
		lookup_failed++;
		return 0;
	}

	restrict_calls++;
	restrict_ret =
		bpf_landlock_restrict_binprm(bprm, ruleset, restrict_flags);
	put_calls++;
	bpf_landlock_put_ruleset(ruleset);

	return 0;
}

SEC("lsm.s/bprm_creds_for_exec")
int BPF_PROG(bprm_creds_for_exec, struct linux_binprm *bprm)
{
	if (!enable_bprm_creds_for_exec)
		return 0;

	return apply_landlock_ruleset(bprm, &bprm_creds_for_exec_hits);
}

SEC("lsm.s/bprm_creds_from_file")
int BPF_PROG(bprm_creds_from_file, struct linux_binprm *bprm,
	     const struct file *file)
{
	(void)file;

	if (!enable_bprm_creds_from_file)
		return 0;

	return apply_landlock_ruleset(bprm, &bprm_creds_from_file_hits);
}
