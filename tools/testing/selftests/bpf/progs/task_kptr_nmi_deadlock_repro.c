// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_TARGET_PIDS 4

enum {
	TASK_KPTR_NMI_MAP_HASH = 1,
	TASK_KPTR_NMI_MAP_ARRAY,
};

enum {
	TASK_KPTR_NMI_ACQUIRE_ERR = 1,
	TASK_KPTR_NMI_CREATE_ERR,
	TASK_KPTR_NMI_LOOKUP_ERR,
	TASK_KPTR_NMI_MAP_ERR,
};

struct task_map_value {
	struct task_struct __kptr * task;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u32);
	__type(value, struct task_map_value);
	__uint(max_entries, MAX_TARGET_PIDS);
} stashed_tasks_hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct task_map_value);
	__uint(max_entries, MAX_TARGET_PIDS);
} stashed_tasks_array SEC(".maps");

struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
void bpf_task_release(struct task_struct *p) __ksym;

__u32 task_kptr_nmi_pids[MAX_TARGET_PIDS];
__u8 task_kptr_nmi_live[MAX_TARGET_PIDS];
__u32 task_kptr_nmi_map_type;
__u32 task_kptr_nmi_inserted;
__u32 task_kptr_nmi_deleted;
__u32 task_kptr_nmi_err;
int task_kptr_nmi_delete_err;

static __always_inline int find_target_slot(__u32 pid)
{
	int i;

	for (i = 0; i < MAX_TARGET_PIDS; i++) {
		if (task_kptr_nmi_pids[i] == pid)
			return i;
	}

	return -1;
}

static __always_inline void stash_task(int i, struct task_map_value *slot,
				       struct task_struct *acquired)
{
	struct task_struct *old;

	old = bpf_kptr_xchg(&slot->task, acquired);
	if (old)
		bpf_task_release(old);
	else {
		task_kptr_nmi_live[i] = 1;
		task_kptr_nmi_inserted++;
	}
}

static __always_inline void set_delete_err(int err)
{
	if (!task_kptr_nmi_delete_err)
		task_kptr_nmi_delete_err = err;
}

SEC("lsm.s/file_open")
int insert_task_kptr_from_lsm(struct file *ctx_file)
{
	struct task_map_value init = {};
	struct task_map_value *slot;
	struct task_struct *task, *acquired;
	__u32 pid;
	int i, ret;

	(void)ctx_file;

	pid = bpf_get_current_pid_tgid() >> 32;
	i = find_target_slot(pid);
	if (i < 0)
		return 0;

	task = bpf_get_current_task_btf();
	acquired = bpf_task_acquire(task);
	if (!acquired) {
		task_kptr_nmi_err = TASK_KPTR_NMI_ACQUIRE_ERR;
		return 0;
	}

	/*
	 * Race is OK for these specific map types. Userspace may
	 * have modified the array, causing inconsistency. This
	 * error TASK_KPTR_NMI_CREATE_ERR is non-fatal for test
	 * purposes. But may be important if this test is
	 * extended for other map types.
	 */
	switch (task_kptr_nmi_map_type) {
	case TASK_KPTR_NMI_MAP_HASH:
		pid = i;
		ret = bpf_map_update_elem(&stashed_tasks_hash, &pid, &init,
					  BPF_NOEXIST);
		if (ret && ret != -EEXIST) {
			task_kptr_nmi_err = TASK_KPTR_NMI_CREATE_ERR;
			goto release_task;
		}
		slot = bpf_map_lookup_elem(&stashed_tasks_hash, &pid);
		if (!slot) {
			task_kptr_nmi_err = TASK_KPTR_NMI_LOOKUP_ERR;
			goto release_task;
		}
		break;
	case TASK_KPTR_NMI_MAP_ARRAY:
		pid = i;
		slot = bpf_map_lookup_elem(&stashed_tasks_array, &pid);
		if (!slot) {
			task_kptr_nmi_err = TASK_KPTR_NMI_LOOKUP_ERR;
			goto release_task;
		}
		break;
	default:
		task_kptr_nmi_err = TASK_KPTR_NMI_MAP_ERR;
		goto release_task;
	}

	stash_task(i, slot, acquired);
	return 0;

release_task:
	bpf_task_release(acquired);
	return 0;
}

static __always_inline void clear_hash_tasks(void)
{
	int i;

	for (i = 0; i < MAX_TARGET_PIDS; i++) {
		__u32 slot = i;

		if (!task_kptr_nmi_pids[i])
			continue;
		if (!bpf_map_delete_elem(&stashed_tasks_hash, &slot)) {
			task_kptr_nmi_live[i] = 0;
			task_kptr_nmi_deleted++;
		} else if (bpf_map_lookup_elem(&stashed_tasks_hash, &slot)) {
			set_delete_err(-EIO);
		}
	}
}

static __always_inline void clear_array_tasks(void)
{
	struct task_map_value init = {};
	int i;

	for (i = 0; i < MAX_TARGET_PIDS; i++) {
		__u32 slot = i;

		if (!task_kptr_nmi_pids[i])
			continue;
		if (bpf_map_update_elem(&stashed_tasks_array, &slot, &init,
					BPF_EXIST)) {
			set_delete_err(-EIO);
			continue;
		}
		if (task_kptr_nmi_live[i]) {
			task_kptr_nmi_live[i] = 0;
			task_kptr_nmi_deleted++;
		}
	}
}

SEC("?tp_btf/nmi_handler")
int BPF_PROG(clear_task_kptrs_from_nmi, void *handler, void *regs, s64 delta_ns,
	     int handled)
{
	(void)handler;
	(void)regs;
	(void)delta_ns;
	(void)handled;

	if (task_kptr_nmi_deleted >= task_kptr_nmi_inserted)
		return 0;

	switch (task_kptr_nmi_map_type) {
	case TASK_KPTR_NMI_MAP_HASH:
		clear_hash_tasks();
		break;
	case TASK_KPTR_NMI_MAP_ARRAY:
		clear_array_tasks();
		break;
	default:
		task_kptr_nmi_err = TASK_KPTR_NMI_MAP_ERR;
		break;
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
