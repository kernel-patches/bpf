// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023, Google LLC. */
#include "vmlinux.h"
#include <asm/unistd.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * We just need the CLONE_VM definition. Without __ASSEMBLY__ sched.h would
 * redefine clone_args, which is already defined by vmlinux.h
 */
#define __ASSEMBLY__
#include <linux/sched.h>
#undef __ASSEMBLY__

#define TEST_TAG 0xf23c39ab

/* Encoding of the test access-type in the tv_nsec parameter. */
enum test_access {
	TEST_SUB_REGION,
	TEST_EQ_REGION,
	TEST_ONE_BY_ONE,
	TEST_ANY_TAG,
};
#define TEST_ACCESS(nsec) ((enum test_access)((nsec) & 0xff))

struct test_data {
	__u64 padding_start;
	__u64 nanosleep_arg;
	__u64 padding_end;
};

struct user_writable {
	void *start;
	size_t size;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct user_writable);
} user_writable SEC(".maps");

int found_user_registered = -1;

/*
 * This is used to test that the contents of per-task bpf_user_writable is sane.
 *
 * It also demonstrates another way (vs. prctl()) how the BPF program can obtain
 * addresses associated with a tag. Beware, however, that this is O(#registered)
 * and a production BPF program should cache its result in task local storage.
 */
static int find_user_registered(__u32 tag, void *start)
{
	const struct bpf_user_writable *uw = bpf_get_current_task_btf()->bpf_user_writable;
	int count = 0;

	if (!uw)
		return count;

      /*
       * Ensure termination of the loop to make the verifier happy. Use
       * bpf_loop() if you expect a very large number of registered regions.
       */
	for (__u32 idx = 0; idx < uw->size && idx < 1024; ++idx) {
		if (uw->entries[idx].tag == tag && uw->entries[idx].start == start)
			count++;
	}

	return count;
}

static void sys_nanosleep(struct pt_regs *regs)
{
	struct __kernel_timespec *ts;
	struct user_writable *w;
	__u32 dummy = -99;
	__u64 tv_nsec;
	int err;

	_Static_assert(sizeof(ts->tv_nsec) == sizeof(tv_nsec), "ABI");

	found_user_registered = -1;

	w = bpf_task_storage_get(&user_writable, bpf_get_current_task_btf(), 0, 0);
	if (!w)
		return;

	ts = (void *)PT_REGS_PARM1_CORE_SYSCALL(regs);
	if (bpf_probe_read_user(&tv_nsec, sizeof(ts->tv_nsec), &ts->tv_nsec))
		return;

	found_user_registered = find_user_registered(TEST_TAG, w->start);

	bpf_printk("doing test accesses");

	/*
	 * Test failing accesses before, so that if they actually succeed, we
	 * won't do the real write and the test will detect a missed write.
	 */
	if (!bpf_probe_write_user_registered(w->start + w->size - 1, &dummy, sizeof(dummy), TEST_TAG))
		return;
	if (!bpf_probe_write_user_registered(w->start - 1, &dummy, sizeof(dummy), TEST_TAG))
		return;
	if (!bpf_probe_write_user_registered(w->start + 100, &dummy, sizeof(dummy), TEST_TAG))
		return;
	if (TEST_ACCESS(tv_nsec) != TEST_ANY_TAG) {
		if (!bpf_probe_write_user_registered(w->start, &dummy, sizeof(dummy), 123))
			return;
		if (!bpf_probe_write_user_registered(w->start, &dummy, sizeof(dummy), 0))
			return;
	}

	switch (TEST_ACCESS(tv_nsec)) {
	case TEST_SUB_REGION:
		bpf_printk("sub region write");
		err = bpf_probe_write_user_registered(w->start + sizeof(__u64), &tv_nsec, sizeof(tv_nsec), TEST_TAG);
		break;
	case TEST_EQ_REGION: {
		struct test_data out = {};

		bpf_printk("whole region write");
		out.nanosleep_arg = tv_nsec;
		err = bpf_probe_write_user_registered(w->start, &out, sizeof(out), TEST_TAG);
		break;
	}
	case TEST_ONE_BY_ONE:
		bpf_printk("write one by one");
		for (int i = 0; i < 3; ++i) {
			err = bpf_probe_write_user_registered(w->start + i * sizeof(__u64), &tv_nsec,
							      sizeof(tv_nsec), TEST_TAG);
			if (err)
				break;
		}
		break;
	case TEST_ANY_TAG:
		bpf_printk("any tag write");
		err = bpf_probe_write_user_registered(w->start + sizeof(__u64), &tv_nsec, sizeof(tv_nsec), 93845);
		break;
	default:
		bpf_printk("unknown access method");
		return;
	}

	if (err)
		bpf_printk("write failed: %d", err);
	else
		bpf_printk("write success");
}

static void sys_prctl(struct pt_regs *regs)
{
	struct user_writable *w;
	__u32 tag;

	if (PT_REGS_PARM1_CORE_SYSCALL(regs) != /*PR_BPF_REGISTER_WRITABLE*/71)
		return;

	tag = (__u32)PT_REGS_PARM4_CORE_SYSCALL(regs);
	if (tag && tag != TEST_TAG)
		return;

	w = bpf_task_storage_get(&user_writable, bpf_get_current_task_btf(), 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!w)
		return;

	bpf_printk("registered user writable region with tag %x", tag);
	w->start = (void *)PT_REGS_PARM2_CORE_SYSCALL(regs);
	w->size = PT_REGS_PARM3_CORE_SYSCALL(regs);
}

SEC("tp_btf/sys_enter")
int BPF_PROG(sys_enter, struct pt_regs *regs, long id)
{
	switch (id) {
	case __NR_prctl:
		sys_prctl(regs);
		break;
	case __NR_nanosleep:
		sys_nanosleep(regs);
		break;
	default:
		break;
	}
	return 0;
}

/*
 * The user writable region is copied on fork(). Also copy the per-task map we
 * use in this test.
 */
SEC("tp_btf/task_newtask")
int BPF_PROG(task_newtask, struct task_struct *t, unsigned long clone_flags)
{
	const struct user_writable *src;
	struct user_writable *dst;

	if (clone_flags & CLONE_VM)
		return 0;

	src = bpf_task_storage_get(&user_writable, bpf_get_current_task_btf(), 0, 0);
	if (!src)
		return 0;

	dst = bpf_task_storage_get(&user_writable, t, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!dst) {
		bpf_printk("failed to copy user_writable on fork()");
		return 0;
	}
	*dst = *src;
	bpf_printk("fork copied user writable region");

	return 0;
}

char _license[] SEC("license") = "GPL";
