// SPDX-License-Identifier: GPL-2.0
/* Copyright © 2026 Justin Suess <utilityemal77@gmail.com> */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct bpf_landlock_ruleset;

extern struct bpf_landlock_ruleset *
bpf_landlock_get_ruleset_from_fd(int fd) __ksym;
extern void
bpf_landlock_put_ruleset(struct bpf_landlock_ruleset *ruleset) __ksym;
extern int bpf_landlock_restrict_binprm(struct linux_binprm *bprm,
					struct bpf_landlock_ruleset *ruleset,
					u32 flags) __ksym;

struct ruleset_slot {
	struct bpf_landlock_ruleset __kptr *ruleset;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct ruleset_slot);
} ruleset_map SEC(".maps");

int monitored_pid;
int ruleset_fd;
u32 kfunc_flags;
bool double_call;
bool got_null_for_bad_fd;
bool no_ruleset;
int restrict_err;
int restrict2_err;
bool called;

/* Runs in the test runner's context through BPF_PROG_RUN:
 * @ruleset_fd is resolved in the runner's fd table and the acquired
 * ruleset is handed to the LSM program through the map kptr slot.
 */
SEC("syscall")
int load_ruleset(void *ctx)
{
	struct bpf_landlock_ruleset *ruleset, *old;
	struct ruleset_slot *slot;
	int key = 0;

	slot = bpf_map_lookup_elem(&ruleset_map, &key);
	if (!slot)
		return 1;

	/* A fd that is not a Landlock ruleset must resolve to NULL. */
	ruleset = bpf_landlock_get_ruleset_from_fd(-1);
	if (!ruleset)
		got_null_for_bad_fd = true;
	else
		bpf_landlock_put_ruleset(ruleset);

	ruleset = bpf_landlock_get_ruleset_from_fd(ruleset_fd);
	if (!ruleset)
		return 2;

	old = bpf_kptr_xchg(&slot->ruleset, ruleset);
	if (old)
		bpf_landlock_put_ruleset(old);
	return 0;
}

SEC("lsm.s/bprm_creds_for_exec")
int BPF_PROG(restrict_exec, struct linux_binprm *bprm)
{
	struct bpf_landlock_ruleset *ruleset, *old;
	struct ruleset_slot *slot;
	int key = 0;

	if (monitored_pid != (bpf_get_current_pid_tgid() >> 32))
		return 0;

	called = true;

	slot = bpf_map_lookup_elem(&ruleset_map, &key);
	if (!slot)
		return 0;

	ruleset = bpf_kptr_xchg(&slot->ruleset, NULL);
	if (!ruleset) {
		no_ruleset = true;
		return 0;
	}

	restrict_err = bpf_landlock_restrict_binprm(bprm, ruleset, kfunc_flags);
	if (double_call)
		/* Replaces the domain staged by the first call. */
		restrict2_err = bpf_landlock_restrict_binprm(bprm, ruleset,
							     kfunc_flags);

	/* Keep the ruleset for the next monitored execution. */
	old = bpf_kptr_xchg(&slot->ruleset, ruleset);
	if (old)
		bpf_landlock_put_ruleset(old);
	return 0;
}
