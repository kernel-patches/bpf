// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define KPTR_DTOR_NMI_MAX_SLOTS 8

enum kptr_dtor_nmi_map_type {
	KPTR_DTOR_NMI_MAP_HASH = 1,
	KPTR_DTOR_NMI_MAP_ARRAY,
};

enum kptr_dtor_nmi_err {
	KPTR_DTOR_NMI_SETUP_CREATE_ERR = 1,
	KPTR_DTOR_NMI_SETUP_LOOKUP_ERR,
	KPTR_DTOR_NMI_SETUP_STALE_ERR,
	KPTR_DTOR_NMI_SETUP_MAP_ERR,
	KPTR_DTOR_NMI_DELETE_ERR,
	KPTR_DTOR_NMI_CLEANUP_ERR,
};

struct kptr_dtor_nmi_value {
	struct bpf_cpumask __kptr * mask;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u32);
	__type(value, struct kptr_dtor_nmi_value);
	__uint(max_entries, KPTR_DTOR_NMI_MAX_SLOTS);
} kptr_dtor_nmi_hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct kptr_dtor_nmi_value);
	__uint(max_entries, KPTR_DTOR_NMI_MAX_SLOTS);
} kptr_dtor_nmi_array SEC(".maps");

struct bpf_cpumask *bpf_cpumask_create(void) __ksym __weak;
void bpf_cpumask_release(struct bpf_cpumask *cpumask) __ksym __weak;

__u32 kptr_dtor_nmi_live_mask;
__u32 kptr_dtor_nmi_map_type;
__u32 kptr_dtor_nmi_setup_created;
__u32 kptr_dtor_nmi_deleted;
__u32 kptr_dtor_nmi_cleanup_deleted;
__u32 kptr_dtor_nmi_release_calls;
__u32 kptr_dtor_nmi_setup_err;
__u32 kptr_dtor_nmi_nmi_err;
__u32 kptr_dtor_nmi_cleanup_err;
int kptr_dtor_nmi_setup_errno;
int kptr_dtor_nmi_nmi_errno;
int kptr_dtor_nmi_cleanup_errno;

static void set_err(__u32 *err_dst, int *errno_dst, __u32 err, int err_no)
{
	if (!*err_dst) {
		*err_dst = err;
		*errno_dst = err_no;
	}
}

static bool slot_is_live(__u32 slot)
{
	return kptr_dtor_nmi_live_mask & (1U << slot);
}

static void mark_slot_live(__u32 slot)
{
	kptr_dtor_nmi_live_mask |= 1U << slot;
}

static void clear_slot_live(__u32 slot)
{
	kptr_dtor_nmi_live_mask &= ~(1U << slot);
}

static struct kptr_dtor_nmi_value *lookup_hash_value(__u32 slot)
{
	return bpf_map_lookup_elem(&kptr_dtor_nmi_hash, &slot);
}

static struct kptr_dtor_nmi_value *lookup_array_value(__u32 slot)
{
	return bpf_map_lookup_elem(&kptr_dtor_nmi_array, &slot);
}

static int stash_mask(struct kptr_dtor_nmi_value *value, __u32 slot)
{
	struct bpf_cpumask *mask, *old;

	mask = bpf_cpumask_create();
	if (!mask)
		return -ENOMEM;

	old = bpf_kptr_xchg(&value->mask, mask);
	if (old) {
		bpf_cpumask_release(old);
		return -EEXIST;
	}

	mark_slot_live(slot);
	kptr_dtor_nmi_setup_created++;
	return 0;
}

static bool populate_hash_slot(__u32 slot)
{
	struct kptr_dtor_nmi_value init = {};
	struct kptr_dtor_nmi_value *value;
	int err;

	err = bpf_map_update_elem(&kptr_dtor_nmi_hash, &slot, &init, BPF_NOEXIST);
	if (err) {
		set_err(&kptr_dtor_nmi_setup_err,
				&kptr_dtor_nmi_setup_errno,
				KPTR_DTOR_NMI_SETUP_CREATE_ERR, err);
		return false;
	}

	value = lookup_hash_value(slot);
	if (!value) {
		set_err(&kptr_dtor_nmi_setup_err,
				&kptr_dtor_nmi_setup_errno,
				KPTR_DTOR_NMI_SETUP_LOOKUP_ERR, -ENOENT);
		return false;
	}

	err = stash_mask(value, slot);
	if (err) {
		set_err(&kptr_dtor_nmi_setup_err,
				&kptr_dtor_nmi_setup_errno,
				KPTR_DTOR_NMI_SETUP_STALE_ERR, err);
		return false;
	}

	return true;
}

static bool populate_array_slot(__u32 slot)
{
	struct kptr_dtor_nmi_value *value;
	int err;

	value = lookup_array_value(slot);
	if (!value) {
		set_err(&kptr_dtor_nmi_setup_err,
				&kptr_dtor_nmi_setup_errno,
				KPTR_DTOR_NMI_SETUP_LOOKUP_ERR, -ENOENT);
		return false;
	}

	err = stash_mask(value, slot);
	if (err) {
		set_err(&kptr_dtor_nmi_setup_err,
				&kptr_dtor_nmi_setup_errno,
				KPTR_DTOR_NMI_SETUP_STALE_ERR, err);
		return false;
	}

	return true;
}

static bool clear_hash_slot_from_nmi(__u32 slot)
{
	struct kptr_dtor_nmi_value *value;
	int err;

	if (!slot_is_live(slot))
		return true;

	err = bpf_map_delete_elem(&kptr_dtor_nmi_hash, &slot);
	if (!err) {
		clear_slot_live(slot);
		kptr_dtor_nmi_deleted++;
		return true;
	}

	/*
	 * Hash deletes take rqspinlock-backed bucket locks. NMI reentry can lose
	 * those acquisitions with -EDEADLK or -ETIMEDOUT even though the slot is
	 * still valid, so leave it live and retry on a later NMI.
	 */
	if (err == -EDEADLK || err == -ETIMEDOUT)
		return true;

	value = lookup_hash_value(slot);
	if (value)
		set_err(&kptr_dtor_nmi_nmi_err,
				&kptr_dtor_nmi_nmi_errno,
				KPTR_DTOR_NMI_DELETE_ERR, err);

	return false;
}

static bool clear_array_slot_from_nmi(__u32 slot)
{
	struct kptr_dtor_nmi_value init = {};
	int err;

	if (!slot_is_live(slot))
		return true;

	err = bpf_map_update_elem(&kptr_dtor_nmi_array, &slot, &init, BPF_EXIST);
	if (err) {
		set_err(&kptr_dtor_nmi_nmi_err,
				&kptr_dtor_nmi_nmi_errno,
				KPTR_DTOR_NMI_DELETE_ERR, err);
		return false;
	}

	clear_slot_live(slot);
	kptr_dtor_nmi_deleted++;
	return true;
}

static bool cleanup_hash_slot(__u32 slot)
{
	struct kptr_dtor_nmi_value *value;
	struct bpf_cpumask *old = NULL;

	value = lookup_hash_value(slot);
	if (!value) {
		clear_slot_live(slot);
		return true;
	}

	old = bpf_kptr_xchg(&value->mask, old);
	if (old) {
		bpf_cpumask_release(old);
		kptr_dtor_nmi_cleanup_deleted++;
	}

	if (bpf_map_delete_elem(&kptr_dtor_nmi_hash, &slot) &&
	    lookup_hash_value(slot)) {
		set_err(&kptr_dtor_nmi_cleanup_err,
				&kptr_dtor_nmi_cleanup_errno,
				KPTR_DTOR_NMI_CLEANUP_ERR, -EIO);
		return false;
	}

	clear_slot_live(slot);
	return true;
}

static bool cleanup_array_slot(__u32 slot)
{
	struct kptr_dtor_nmi_value *value;
	struct bpf_cpumask *old = NULL;

	value = lookup_array_value(slot);
	if (!value) {
		set_err(&kptr_dtor_nmi_cleanup_err,
				&kptr_dtor_nmi_cleanup_errno,
				KPTR_DTOR_NMI_CLEANUP_ERR, -ENOENT);
		return false;
	}

	old = bpf_kptr_xchg(&value->mask, old);
	if (old) {
		bpf_cpumask_release(old);
		kptr_dtor_nmi_cleanup_deleted++;
	}

	clear_slot_live(slot);
	return true;
}

static void populate_hash_masks(void)
{
	__u32 slot;

	for (slot = 0; slot < KPTR_DTOR_NMI_MAX_SLOTS; slot++) {
		if (!populate_hash_slot(slot))
			return;
	}
}

static void populate_array_masks(void)
{
	__u32 slot;

	for (slot = 0; slot < KPTR_DTOR_NMI_MAX_SLOTS; slot++) {
		if (!populate_array_slot(slot))
			return;
	}
}

static void clear_hash_masks_from_nmi(void)
{
	__u32 slot;

	for (slot = 0; slot < KPTR_DTOR_NMI_MAX_SLOTS; slot++) {
		if (!clear_hash_slot_from_nmi(slot))
			return;
	}
}

static void clear_array_masks_from_nmi(void)
{
	__u32 slot;

	for (slot = 0; slot < KPTR_DTOR_NMI_MAX_SLOTS; slot++) {
		if (!clear_array_slot_from_nmi(slot))
			return;
	}
}

static void cleanup_hash_masks(void)
{
	__u32 slot;

	for (slot = 0; slot < KPTR_DTOR_NMI_MAX_SLOTS; slot++) {
		if (!cleanup_hash_slot(slot))
			return;
	}
}

static void cleanup_array_masks(void)
{
	__u32 slot;

	for (slot = 0; slot < KPTR_DTOR_NMI_MAX_SLOTS; slot++) {
		if (!cleanup_array_slot(slot))
			return;
	}
}

SEC("syscall")
int populate_kptrs(void *ctx)
{
	(void)ctx;

	switch (kptr_dtor_nmi_map_type) {
	case KPTR_DTOR_NMI_MAP_HASH:
		populate_hash_masks();
		break;
	case KPTR_DTOR_NMI_MAP_ARRAY:
		populate_array_masks();
		break;
	default:
		set_err(&kptr_dtor_nmi_setup_err,
			&kptr_dtor_nmi_setup_errno,
			KPTR_DTOR_NMI_SETUP_MAP_ERR, -EINVAL);
		break;
	}

	return 0;
}

SEC("syscall")
int cleanup_kptrs(void *ctx)
{
	(void)ctx;

	switch (kptr_dtor_nmi_map_type) {
	case KPTR_DTOR_NMI_MAP_HASH:
		cleanup_hash_masks();
		break;
	case KPTR_DTOR_NMI_MAP_ARRAY:
		cleanup_array_masks();
		break;
	default:
		set_err(&kptr_dtor_nmi_cleanup_err,
			&kptr_dtor_nmi_cleanup_errno,
			KPTR_DTOR_NMI_CLEANUP_ERR, -EINVAL);
		break;
	}

	return 0;
}

SEC("tp_btf/nmi_handler")
int BPF_PROG(clear_kptrs_from_nmi, void *handler, void *regs, s64 delta_ns,
	     int handled)
{
	(void)handler;
	(void)regs;
	(void)delta_ns;
	(void)handled;

	if (kptr_dtor_nmi_deleted >= kptr_dtor_nmi_setup_created)
		return 0;

	switch (kptr_dtor_nmi_map_type) {
	case KPTR_DTOR_NMI_MAP_HASH:
		clear_hash_masks_from_nmi();
		break;
	case KPTR_DTOR_NMI_MAP_ARRAY:
		clear_array_masks_from_nmi();
		break;
	default:
		set_err(&kptr_dtor_nmi_nmi_err,
			&kptr_dtor_nmi_nmi_errno,
			KPTR_DTOR_NMI_DELETE_ERR, -EINVAL);
		break;
	}

	return 0;
}

SEC("fentry/bpf_cpumask_release")
int BPF_PROG(count_cpumask_release, struct bpf_cpumask *mask)
{
	(void)mask;
	kptr_dtor_nmi_release_calls++;
	return 0;
}

char _license[] SEC("license") = "GPL";
