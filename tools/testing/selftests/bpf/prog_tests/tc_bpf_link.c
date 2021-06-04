// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <linux/pkt_cls.h>

#include "test_tc_bpf.skel.h"

#define LO_IFINDEX 1

static int test_tc_bpf_link_basic(struct bpf_tc_hook *hook,
				  struct bpf_program *prog)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_link_opts, opts, .handle = 1, .priority = 1);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, qopts, .handle = 1, .priority = 1);
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	struct bpf_link *link, *invl;
	int ret;

	link = bpf_program__attach_tc(prog, hook, &opts);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_tc"))
		return PTR_ERR(link);

	ret = bpf_obj_get_info_by_fd(bpf_program__fd(prog), &info, &info_len);
	if (!ASSERT_OK(ret, "bpf_obj_get_info_by_fd"))
		goto end;

	ret = bpf_tc_query(hook, &qopts);
	if (!ASSERT_OK(ret, "bpf_tc_query"))
		goto end;

	if (!ASSERT_EQ(qopts.prog_id, info.id, "prog_id match"))
		goto end;

	opts.gen_flags = ~0u;
	invl = bpf_program__attach_tc(prog, hook, &opts);
	if (!ASSERT_ERR_PTR(invl, "bpf_program__attach_tc with invalid flags")) {
		bpf_link__destroy(invl);
		ret = -EINVAL;
	}

end:
	bpf_link__destroy(link);
	return ret;
}

static int test_tc_bpf_link_netlink_interaction(struct bpf_tc_hook *hook,
						struct bpf_program *prog)
{
	DECLARE_LIBBPF_OPTS(bpf_link_update_opts, lopts,
			    .old_prog_fd = bpf_program__fd(prog));
	DECLARE_LIBBPF_OPTS(bpf_tc_link_opts, opts, .handle = 1, .priority = 1);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, nopts, .handle = 1, .priority = 1);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, dopts, .handle = 1, .priority = 1);
	struct bpf_link *link;
	int ret;

	/* We need to test the following cases:
	 *	1. BPF link owned filter cannot be replaced by netlink
	 *	2. Netlink owned filter cannot be replaced by BPF link
	 *	3. Netlink cannot do targeted delete of BPF link owned filter
	 *	4. Filter is actually deleted (with chain cleanup)
	 *	   We actually (ab)use the kernel behavior of returning EINVAL when
	 *	   target chain doesn't exist on tc_get_tfilter (which maps to
	 *	   bpf_tc_query) here, to know if the chain was really cleaned
	 *	   up on tcf_proto destruction. Our setup is so that there is
	 *	   only one reference to the chain.
	 *
	 *	   So on query, chain ? (filter ?: ENOENT) : EINVAL
	 */

	link = bpf_program__attach_tc(prog, hook, &opts);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_tc"))
		return PTR_ERR(link);

	nopts.prog_fd = bpf_program__fd(prog);
	ret = bpf_tc_attach(hook, &nopts);
	if (!ASSERT_EQ(ret, -EEXIST, "bpf_tc_attach without replace"))
		goto end;

	nopts.flags = BPF_TC_F_REPLACE;
	ret = bpf_tc_attach(hook, &nopts);
	if (!ASSERT_EQ(ret, -EPERM, "bpf_tc_attach with replace"))
		goto end;

	ret = bpf_tc_detach(hook, &dopts);
	if (!ASSERT_EQ(ret, -EPERM, "bpf_tc_detach"))
		goto end;

	lopts.flags = BPF_F_REPLACE;
	ret = bpf_link_update(bpf_link__fd(link), bpf_program__fd(prog),
			      &lopts);
	ASSERT_OK(ret, "bpf_link_update");
	ret = ret < 0 ? -errno : ret;

end:
	bpf_link__destroy(link);
	if (!ret && !ASSERT_EQ(bpf_tc_query(hook, &dopts), -EINVAL,
			       "chain empty delete"))
		ret = -EINVAL;
	return ret;
}

static int test_tc_bpf_link_update_ways(struct bpf_tc_hook *hook,
					struct bpf_program *prog)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_link_opts, opts, .handle = 1, .priority = 1);
	DECLARE_LIBBPF_OPTS(bpf_link_update_opts, uopts, 0);
	struct test_tc_bpf *skel;
	struct bpf_link *link;
	int ret;

	skel = test_tc_bpf__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_tc_bpf__open_and_load"))
		return PTR_ERR(skel);

	link = bpf_program__attach_tc(prog, hook, &opts);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_tc")) {
		ret = PTR_ERR(link);
		goto end;
	}

	ret = bpf_link_update(bpf_link__fd(link), bpf_program__fd(prog),
			      &uopts);
	if (!ASSERT_OK(ret, "bpf_link_update no old prog"))
		goto end;

	uopts.old_prog_fd = bpf_program__fd(prog);
	ret = bpf_link_update(bpf_link__fd(link), bpf_program__fd(prog),
			      &uopts);
	if (!ASSERT_TRUE(ret < 0 && errno == EINVAL,
			 "bpf_link_update with old prog without BPF_F_REPLACE")) {
		ret = -EINVAL;
		goto end;
	}

	uopts.flags = BPF_F_REPLACE;
	ret = bpf_link_update(bpf_link__fd(link), bpf_program__fd(prog),
			      &uopts);
	if (!ASSERT_OK(ret, "bpf_link_update with old prog with BPF_F_REPLACE"))
		goto end;

	uopts.old_prog_fd = bpf_program__fd(skel->progs.cls);
	ret = bpf_link_update(bpf_link__fd(link), bpf_program__fd(prog),
			      &uopts);
	if (!ASSERT_TRUE(ret < 0 && errno == EINVAL,
			 "bpf_link_update with wrong old prog")) {
		ret = -EINVAL;
		goto end;
	}
	ret = 0;

end:
	test_tc_bpf__destroy(skel);
	return ret;
}

static int test_tc_bpf_link_info_api(struct bpf_tc_hook *hook,
				     struct bpf_program *prog)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_link_opts, opts, .handle = 1, .priority = 1);
	__u32 ifindex, parent, handle, gen_flags, priority;
	char buf[4096], path[256], *begin;
	struct bpf_link_info info = {};
	__u32 info_len = sizeof(info);
	struct bpf_link *link;
	int ret, fdinfo;

	link = bpf_program__attach_tc(prog, hook, &opts);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_tc"))
		return PTR_ERR(link);

	ret = bpf_obj_get_info_by_fd(bpf_link__fd(link), &info, &info_len);
	if (!ASSERT_OK(ret, "bpf_obj_get_info_by_fd"))
		goto end;

	ret = snprintf(path, sizeof(path), "/proc/self/fdinfo/%d",
		       bpf_link__fd(link));
	if (!ASSERT_TRUE(!ret || ret < sizeof(path), "snprintf pathname"))
		goto end;

	fdinfo = open(path, O_RDONLY);
	if (!ASSERT_GT(fdinfo, -1, "open fdinfo"))
		goto end;

	ret = read(fdinfo, buf, sizeof(buf));
	if (!ASSERT_GT(ret, 0, "read fdinfo")) {
		ret = -EINVAL;
		goto end_file;
	}

	begin = strstr(buf, "ifindex");
	if (!ASSERT_OK_PTR(begin, "find beginning of fdinfo info")) {
		ret = -EINVAL;
		goto end_file;
	}

	ret = sscanf(begin, "ifindex:\t%u\n"
			    "parent:\t%u\n"
			    "handle:\t%u\n"
			    "priority:\t%u\n"
			    "gen_flags:\t%u\n",
			    &ifindex, &parent, &handle, &priority, &gen_flags);
	if (!ASSERT_EQ(ret, 5, "sscanf fdinfo")) {
		ret = -EINVAL;
		goto end_file;
	}

	ret = -EINVAL;

#define X(a, b, c) (!ASSERT_EQ(a, b, #a " == " #b) || !ASSERT_EQ(b, c, #b " == " #c))
	if (X(info.tc.ifindex, ifindex, 1) ||
	    X(info.tc.parent, parent,
	      TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS)) ||
	    X(info.tc.handle, handle, 1) ||
	    X(info.tc.gen_flags, gen_flags, TCA_CLS_FLAGS_NOT_IN_HW) ||
	    X(info.tc.priority, priority, 1))
#undef X
		goto end_file;

	ret = 0;

end_file:
	close(fdinfo);
end:
	bpf_link__destroy(link);
	return ret;
}

void test_tc_bpf_link(void)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = LO_IFINDEX,
			    .attach_point = BPF_TC_INGRESS);
	struct test_tc_bpf *skel = NULL;
	bool hook_created = false;
	int ret;

	skel = test_tc_bpf__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_tc_bpf__open_and_load"))
		return;

	ret = bpf_tc_hook_create(&hook);
	if (ret == 0)
		hook_created = true;

	ret = ret == -EEXIST ? 0 : ret;
	if (!ASSERT_OK(ret, "bpf_tc_hook_create(BPF_TC_INGRESS)"))
		goto end;

	ret = test_tc_bpf_link_basic(&hook, skel->progs.cls);
	if (!ASSERT_OK(ret, "test_tc_bpf_link_basic"))
		goto end;

	bpf_tc_hook_destroy(&hook);

	hook.attach_point = BPF_TC_EGRESS;
	ret = test_tc_bpf_link_basic(&hook, skel->progs.cls);
	if (!ASSERT_OK(ret, "test_tc_bpf_link_basic"))
		goto end;

	bpf_tc_hook_destroy(&hook);

	ret = test_tc_bpf_link_netlink_interaction(&hook, skel->progs.cls);
	if (!ASSERT_OK(ret, "test_tc_bpf_link_netlink_interaction"))
		goto end;

	bpf_tc_hook_destroy(&hook);

	ret = test_tc_bpf_link_update_ways(&hook, skel->progs.cls);
	if (!ASSERT_OK(ret, "test_tc_bpf_link_update_ways"))
		goto end;

	bpf_tc_hook_destroy(&hook);

	ret = test_tc_bpf_link_info_api(&hook, skel->progs.cls);
	if (!ASSERT_OK(ret, "test_tc_bpf_link_info_api"))
		goto end;

end:
	if (hook_created) {
		hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
		bpf_tc_hook_destroy(&hook);
	}
	test_tc_bpf__destroy(skel);
}
