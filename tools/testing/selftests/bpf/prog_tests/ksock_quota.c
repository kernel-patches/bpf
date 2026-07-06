// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Isovalent */

#include <sys/stat.h>

#include "test_progs.h"
#include "network_helpers.h"
#include "sysctl_helpers.h"
#include "ksock_quota.skel.h"

#define NS_NET_QUOTA_TEST1 "ksock_net_quota_ns1"
#define NS_NET_QUOTA_TEST2 "ksock_net_quota_ns2"
#define KSOCK_MAX_SYSCTL "/proc/sys/net/core/bpf_ksock_max"
#define KSOCK_QUOTA_NS_SLOTS 3
#define KSOCK_QUOTA_NS1_OFFSET 0
#define KSOCK_QUOTA_NS2_OFFSET KSOCK_QUOTA_NS_SLOTS

static int ksock_run_prog(struct bpf_program *prog)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	if (err)
		return err;
	return opts.retval;
}

static __u64 ksock_quota_release_completed(struct ksock_quota *skel)
{
	return __atomic_load_n(&skel->bss->quota_release_completed,
			       __ATOMIC_ACQUIRE);
}

static int ksock_release_quota_slots(struct ksock_quota *skel, int slot_offset)
{
	__u64 completed;
	int err;

	completed = ksock_quota_release_completed(skel);
	skel->bss->quota_slot_offset = slot_offset;
	err = ksock_run_prog(skel->progs.ksock_quota_release);
	if (!ASSERT_OK(err, "ksock_quota_release"))
		return -1;

	while (ksock_quota_release_completed(skel) - completed <
	       skel->bss->quota_released)
		usleep(1000);

	return skel->bss->quota_released;
}

static bool ksock_expect_quota(struct ksock_quota *skel, int slot_offset,
			       const char *name)
{
	int err;

	skel->bss->quota_slot_offset = slot_offset;
	err = ksock_run_prog(skel->progs.ksock_quota_create);
	if (!ASSERT_OK(err, name))
		return false;
	if (!ASSERT_EQ(skel->bss->quota_created, 2, name))
		return false;
	return ASSERT_EQ(skel->bss->quota_err, -ENOSPC, name);
}

static bool record_current_ns(struct ksock_quota *skel, int target)
{
	struct stat st;
	int err;

	err = stat("/proc/self/ns/net", &st);
	if (!ASSERT_OK(err, "stat netns"))
		return false;
	skel->bss->target_netns_inum[target] = (__u32)st.st_ino;
	return true;
}

void serial_test_ksock_net_quota(void)
{
	char old_max[16] = {};
	struct netns_obj *netns1 = NULL, *netns2 = NULL;
	struct ksock_quota *skel;
	int released;

	skel = ksock_quota__open_and_load();
	if (!ASSERT_OK_PTR(skel, "ksock quota skeleton"))
		return;
	skel->links.ksock_release_work_enter =
		bpf_program__attach_trace(skel->progs.ksock_release_work_enter);
	if (!ASSERT_OK_PTR(skel->links.ksock_release_work_enter,
			   "attach ksock release work entry"))
		goto out;
	skel->links.ksock_release_work_exit =
		bpf_program__attach_trace(skel->progs.ksock_release_work_exit);
	if (!ASSERT_OK_PTR(skel->links.ksock_release_work_exit,
			   "attach ksock release work exit"))
		goto out;

	if (sysctl_set_or_fail(KSOCK_MAX_SYSCTL, old_max, "2"))
		goto out;

	netns1 = netns_new(NS_NET_QUOTA_TEST1, true);
	if (!ASSERT_OK_PTR(netns1, "create first netns"))
		goto out;
	if (!record_current_ns(skel, 0))
		goto out;

	if (!ksock_expect_quota(skel, KSOCK_QUOTA_NS1_OFFSET,
				"first netns quota"))
		goto out;

	/* The host-wide setting grants the full allowance to each netns. */
	netns2 = netns_new(NS_NET_QUOTA_TEST2, true);
	if (!ASSERT_OK_PTR(netns2, "create second netns"))
		goto out;
	if (!record_current_ns(skel, 1))
		goto out;

	if (!ksock_expect_quota(skel, KSOCK_QUOTA_NS2_OFFSET,
				"second netns quota"))
		goto out;

	released = ksock_release_quota_slots(skel, KSOCK_QUOTA_NS2_OFFSET);
	if (!ASSERT_EQ(released, 2, "second netns quota released"))
		goto out;

	/* Both released slots must become available again. */
	ksock_expect_quota(skel, KSOCK_QUOTA_NS2_OFFSET, "recovered quota");

out:
	ksock_release_quota_slots(skel, KSOCK_QUOTA_NS2_OFFSET);
	ksock_release_quota_slots(skel, KSOCK_QUOTA_NS1_OFFSET);
	netns_free(netns2);
	netns_free(netns1);
	if (old_max[0])
		sysctl_set_or_fail(KSOCK_MAX_SYSCTL, NULL, old_max);
	ksock_quota__destroy(skel);
}
