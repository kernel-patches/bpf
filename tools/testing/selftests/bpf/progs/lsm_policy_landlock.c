// SPDX-License-Identifier: GPL-2.0
/* Copyright © 2026 Justin Suess <utilityemal77@gmail.com> */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

extern struct lsm_policy_object *
bpf_lsm_policy_acquire(struct lsm_policy_object *object) __ksym;
extern int bpf_lsm_policy_apply_bprm(struct lsm_policy_object *object,
				     struct linux_binprm *bprm,
				     u32 flags) __ksym;
extern struct lsm_policy_object *
bpf_lsm_policy_from_fd(int fd, u32 flags) __ksym;
extern void bpf_lsm_policy_release(struct lsm_policy_object *object) __ksym;
void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;

struct policy_slot {
	struct lsm_policy_object __kptr *object;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct policy_slot);
} policy_map SEC(".maps");

int monitored_pid;
int monitored_pid2;
int ruleset_fd;
u32 kfunc_flags;
bool double_call;
u32 policy_type;
u64 policy_lsmid;
bool no_policy;
int restrict_err;
int restrict2_err;
int restrict_ok_count;
bool called;
u64 enforce_domain_id;
int enforce_count;
bool enforce_complete;
bool enforce_process_wide;
bool enforce_no_new_privs;

/*
 * Runs in the test runner's context through BPF_PROG_RUN, where
 * @ruleset_fd is meaningful.
 */
SEC("syscall")
int load_policy(void *ctx)
{
	struct lsm_policy_object *object, *old;
	struct policy_slot *slot;
	int key = 0;

	slot = bpf_map_lookup_elem(&policy_map, &key);
	if (!slot)
		return 1;

	object = bpf_lsm_policy_from_fd(ruleset_fd, 0);
	if (!object)
		return 2;

	/*
	 * The object's identity is BTF-readable off the trusted kptr: a
	 * program that expects a policy of one specific LSM can check
	 * the lsmid the fd resolved to.
	 */
	policy_type = object->type;
	policy_lsmid = object->lsmid;

	old = bpf_kptr_xchg(&slot->object, object);
	if (old)
		bpf_lsm_policy_release(old);
	return 0;
}

SEC("lsm.s/bprm_creds_for_exec")
int BPF_PROG(restrict_exec, struct linux_binprm *bprm)
{
	struct lsm_policy_object *object;
	struct policy_slot *slot;
	int pid = bpf_get_current_pid_tgid() >> 32;
	int key = 0;

	if (pid != monitored_pid && pid != monitored_pid2)
		return 0;

	called = true;

	slot = bpf_map_lookup_elem(&policy_map, &key);
	if (!slot)
		return 0;

	/*
	 * RCU load + acquire instead of bpf_kptr_xchg(): the slot is
	 * never emptied, so concurrent executions can share it.
	 */
	bpf_rcu_read_lock();
	object = slot->object;
	if (object)
		object = bpf_lsm_policy_acquire(object);
	bpf_rcu_read_unlock();

	if (!object) {
		no_policy = true;
		return 0;
	}

	restrict_err = bpf_lsm_policy_apply_bprm(object, bprm, kfunc_flags);
	if (!restrict_err)
		__sync_fetch_and_add(&restrict_ok_count, 1);
	if (double_call)
		/* Replaces the domain staged by the first call. */
		restrict2_err = bpf_lsm_policy_apply_bprm(object, bprm,
							  kfunc_flags);

	bpf_lsm_policy_release(object);
	return 0;
}

SEC("tp_btf/landlock_enforce_domain")
int BPF_PROG(on_enforce_domain, struct landlock_domain *domain, bool complete,
	     bool process_wide, bool no_new_privs)
{
	int pid = bpf_get_current_pid_tgid() >> 32;

	if (pid != monitored_pid && pid != monitored_pid2)
		return 0;

	__sync_fetch_and_add(&enforce_count, 1);
	enforce_domain_id = domain->hierarchy->id;
	enforce_complete = complete;
	enforce_process_wide = process_wide;
	enforce_no_new_privs = no_new_privs;
	return 0;
}
