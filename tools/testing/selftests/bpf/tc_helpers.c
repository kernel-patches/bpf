// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include <net/if.h>
#include "tc_helpers.h"
#include "test_progs.h"

static int attach_tc_prog(int ifindex, int igr_fd, int egr_fd)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
			    .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts1, .handle = 1,
			    .priority = 1, .prog_fd = igr_fd);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts2, .handle = 1,
			    .priority = 1, .prog_fd = egr_fd);
	int ret;

	ret = bpf_tc_hook_create(&hook);
	if (!ASSERT_OK(ret, "create tc hook"))
		return ret;

	if (igr_fd >= 0) {
		hook.attach_point = BPF_TC_INGRESS;
		ret = bpf_tc_attach(&hook, &opts1);
		if (!ASSERT_OK(ret, "bpf_tc_attach")) {
			bpf_tc_hook_destroy(&hook);
			return ret;
		}
	}

	if (egr_fd >= 0) {
		hook.attach_point = BPF_TC_EGRESS;
		ret = bpf_tc_attach(&hook, &opts2);
		if (!ASSERT_OK(ret, "bpf_tc_attach")) {
			bpf_tc_hook_destroy(&hook);
			return ret;
		}
	}

	return 0;
}

int generic_attach(const char *dev, int igr_fd, int egr_fd)
{
	int ifindex;

	if (!ASSERT_OK_FD(igr_fd, "check ingress fd"))
		return -1;
	if (!ASSERT_OK_FD(egr_fd, "check egress fd"))
		return -1;

	ifindex = if_nametoindex(dev);
	if (!ASSERT_NEQ(ifindex, 0, "get ifindex"))
		return -1;

	return attach_tc_prog(ifindex, igr_fd, egr_fd);
}

int generic_attach_igr(const char *dev, int igr_fd)
{
	int ifindex;

	if (!ASSERT_OK_FD(igr_fd, "check ingress fd"))
		return -1;

	ifindex = if_nametoindex(dev);
	if (!ASSERT_NEQ(ifindex, 0, "get ifindex"))
		return -1;

	return attach_tc_prog(ifindex, igr_fd, -1);
}

int generic_attach_egr(const char *dev, int egr_fd)
{
	int ifindex;

	if (!ASSERT_OK_FD(egr_fd, "check egress fd"))
		return -1;

	ifindex = if_nametoindex(dev);
	if (!ASSERT_NEQ(ifindex, 0, "get ifindex"))
		return -1;

	return attach_tc_prog(ifindex, -1, egr_fd);
}


