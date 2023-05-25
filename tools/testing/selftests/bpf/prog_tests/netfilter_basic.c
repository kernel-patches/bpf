// SPDX-License-Identifier: GPL-2.0-or-later

#include <netinet/in.h>
#include <linux/netfilter.h>

#include "test_progs.h"
#include "test_netfilter_link_attach.skel.h"

struct nf_hook_options {
	__u32 pf;
	__u32 hooknum;
	__s32 priority;
	__u32 flags;

	bool expect_success;
};

struct nf_hook_options nf_hook_attach_tests[] = {
	{  },
	{ .pf = NFPROTO_NUMPROTO, },
	{ .pf = NFPROTO_IPV4, .hooknum = 42, },
	{ .pf = NFPROTO_IPV4, .priority = INT_MIN },
	{ .pf = NFPROTO_IPV4, .priority = INT_MAX },
	{ .pf = NFPROTO_IPV4, .flags = UINT_MAX },

	{ .pf = NFPROTO_INET, .priority = 1, },

	{ .pf = NFPROTO_IPV4, .priority = -10000, .expect_success = true },
	{ .pf = NFPROTO_IPV6, .priority = 10001, .expect_success = true },
};

static void __test_netfilter_link_attach(struct bpf_program *prog)
{
	LIBBPF_OPTS(bpf_netfilter_opts, opts);
	int i;

	for (i = 0; i < ARRAY_SIZE(nf_hook_attach_tests); i++) {
		struct bpf_link *link;

#define X(opts, m, i)	opts.m = nf_hook_attach_tests[(i)].m
		X(opts, pf, i);
		X(opts, hooknum, i);
		X(opts, priority, i);
		X(opts, flags, i);
#undef X
		link = bpf_program__attach_netfilter_opts(prog, &opts);
		if (nf_hook_attach_tests[i].expect_success) {
			struct bpf_link *link2;

			if (!ASSERT_OK_PTR(link, "program attach successful"))
				continue;

			link2 = bpf_program__attach_netfilter_opts(prog, &opts);
			ASSERT_NULL(link2, "attach program with same pf/hook/priority");

			if (!ASSERT_EQ(bpf_link__destroy(link), 0, "link destroy"))
				break;

			link2 = bpf_program__attach_netfilter_opts(prog, &opts);
			if (!ASSERT_OK_PTR(link2, "program reattach successful"))
				continue;
			if (!ASSERT_EQ(bpf_link__destroy(link2), 0, "link destroy"))
				break;
		} else {
			ASSERT_NULL(link, "program load failure");
		}
	}
}

static void test_netfilter_link_attach(void)
{
	struct test_netfilter_link_attach *skel;

	skel = test_netfilter_link_attach__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_netfilter_link_attach__open_and_load"))
		goto out;

	__test_netfilter_link_attach(skel->progs.nf_link_attach_test);
out:
	test_netfilter_link_attach__destroy(skel);
}

void test_netfilter_basic(void)
{
	if (test__start_subtest("netfilter link attach"))
		test_netfilter_link_attach();
}
