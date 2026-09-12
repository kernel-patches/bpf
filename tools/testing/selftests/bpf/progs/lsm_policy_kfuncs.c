// SPDX-License-Identifier: GPL-2.0
/* Copyright © 2026 Justin Suess <utilityemal77@gmail.com> */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

extern struct lsm_policy_object *
bpf_lsm_policy_from_fd(int fd, u32 flags) __ksym;
extern void bpf_lsm_policy_release(struct lsm_policy_object *object) __ksym;

int plain_fd;
bool got_null_for_bad_fd;
bool got_null_for_plain_fd;
bool got_null_for_bad_flags;

/*
 * Runs in the test runner's context through BPF_PROG_RUN, where
 * @plain_fd is meaningful.
 */
SEC("syscall")
int check_from_fd(void *ctx)
{
	struct lsm_policy_object *object;

	/* A fd not open in this task's fd table must resolve to NULL. */
	object = bpf_lsm_policy_from_fd(-1, 0);
	if (!object)
		got_null_for_bad_fd = true;
	else
		bpf_lsm_policy_release(object);

	/*
	 * A valid fd that is not any LSM's policy object must be
	 * declined by every LSM and resolve to NULL.
	 */
	object = bpf_lsm_policy_from_fd(plain_fd, 0);
	if (!object)
		got_null_for_plain_fd = true;
	else
		bpf_lsm_policy_release(object);

	/* The flags are reserved: any nonzero value must resolve to NULL. */
	object = bpf_lsm_policy_from_fd(plain_fd, 1);
	if (!object)
		got_null_for_bad_flags = true;
	else
		bpf_lsm_policy_release(object);

	return 0;
}
