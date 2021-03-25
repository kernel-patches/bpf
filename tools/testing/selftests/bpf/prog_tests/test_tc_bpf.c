// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/err.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <test_progs.h>
#include <linux/if_ether.h>

#define LO_IFINDEX 1

static int test_tc_cls_internal(int fd, __u32 parent_id)
{
	struct bpf_tc_cls_attach_id id = {};
	struct bpf_tc_cls_info info = {};
	int ret;
	DECLARE_LIBBPF_OPTS(bpf_tc_cls_opts, opts, .handle = 1, .priority = 10,
			    .class_id = TC_H_MAKE(1UL << 16, 1),
			    .chain_index = 5);

	ret = bpf_tc_cls_attach_dev(fd, LO_IFINDEX, parent_id, ETH_P_IP, &opts,
				    &id);
	if (CHECK_FAIL(ret < 0))
		return ret;

	ret = bpf_tc_cls_get_info_dev(fd, LO_IFINDEX, parent_id, ETH_P_IP, NULL,
				      &info);
	if (CHECK_FAIL(ret < 0))
		goto end;

	ret = -1;

	if (CHECK_FAIL(info.id.ifindex != id.ifindex) ||
	    CHECK_FAIL(info.id.parent_id != id.parent_id) ||
	    CHECK_FAIL(info.id.handle != id.handle) ||
	    CHECK_FAIL(info.id.protocol != id.protocol) ||
	    CHECK_FAIL(info.id.chain_index != id.chain_index) ||
	    CHECK_FAIL(info.id.priority != id.priority) ||
	    CHECK_FAIL(info.id.ifindex != LO_IFINDEX) ||
	    CHECK_FAIL(info.id.parent_id != parent_id) ||
	    CHECK_FAIL(info.id.handle != 1) ||
	    CHECK_FAIL(info.id.priority != 10) ||
	    CHECK_FAIL(info.id.protocol != ETH_P_IP) ||
	    CHECK_FAIL(info.class_id != TC_H_MAKE(1UL << 16, 1)) ||
	    CHECK_FAIL(info.id.chain_index != 5))
		goto end;

	opts.direct_action = true;
	ret = bpf_tc_cls_replace_dev(fd, id.ifindex, id.parent_id, id.protocol,
				     &opts, &id);
	if (CHECK_FAIL(ret < 0))
		return ret;

end:;
	ret = bpf_tc_cls_detach_dev(&id);
	CHECK_FAIL(ret < 0);
	return ret;
}

static int test_tc_cls(struct bpf_program *prog, __u32 parent_id)
{
	struct bpf_tc_cls_info info = {};
	struct bpf_link *link;
	int ret;
	DECLARE_LIBBPF_OPTS(bpf_tc_cls_opts, opts, .priority = 10, .handle = 1,
			    .class_id = TC_H_MAKE(1UL << 16, 1));

	link = bpf_program__attach_tc_cls_dev(prog, LO_IFINDEX, parent_id,
					      ETH_P_ALL, &opts);
	if (CHECK_FAIL(IS_ERR_OR_NULL(link)))
		return PTR_ERR(link);

	ret = bpf_tc_cls_get_info_dev(bpf_program__fd(prog), LO_IFINDEX,
				      parent_id, ETH_P_ALL, NULL, &info);
	if (CHECK_FAIL(ret < 0))
		goto end;

	ret = -1;

	if (CHECK_FAIL(info.id.ifindex != LO_IFINDEX) ||
	    CHECK_FAIL(info.id.handle != 1) ||
	    CHECK_FAIL(info.id.priority != 10) ||
	    CHECK_FAIL(info.id.protocol != ETH_P_ALL) ||
	    CHECK_FAIL(info.class_id != TC_H_MAKE(1UL << 16, 1)))
		goto end;

	/* Demonstrate changing attributes (e.g. to direct action) */
	opts.class_id = TC_H_MAKE(1UL << 16, 2);
	opts.direct_action = true;

	/* Disconnect as we drop to the lower level API, which invalidates the
	 * link.
	 */
	bpf_link__disconnect(link);

	ret = bpf_tc_cls_change_dev(bpf_program__fd(prog), info.id.ifindex,
				    info.id.parent_id, info.id.protocol, &opts,
				    &info.id);
	if (CHECK_FAIL(ret < 0))
		goto end;

	ret = bpf_tc_cls_get_info_dev(bpf_program__fd(prog), info.id.ifindex,
				      info.id.parent_id, info.id.protocol, NULL,
				      &info);
	if (CHECK_FAIL(ret < 0))
		goto end;

	ret = -1;

	if (CHECK_FAIL(info.class_id != TC_H_MAKE(1UL << 16, 2)))
		goto end;
	if (CHECK_FAIL((info.bpf_flags & TCA_BPF_FLAG_ACT_DIRECT) != 1))
		goto end;

	ret = bpf_tc_cls_detach_dev(&info.id);
	if (CHECK_FAIL(ret < 0))
		goto end;

end:
	ret = bpf_link__destroy(link);
	CHECK_FAIL(ret < 0);
	return ret;
}

static int test_tc_act_internal(int fd)
{
	struct bpf_tc_act_info info = {};
	__u32 index = 0;
	int ret;
	DECLARE_LIBBPF_OPTS(bpf_tc_act_opts, opts, 0);

	ret = bpf_tc_act_attach(fd, &opts, &index);
	if (CHECK_FAIL(ret < 0 || !index))
		goto end;

	index = 0;
	ret = bpf_tc_act_attach(fd, &opts, &index);
	if (CHECK_FAIL(ret < 0 || !index))
		goto end;

	opts.index = 3;
	index = 0;
	ret = bpf_tc_act_attach(fd, &opts, &index);
	if (CHECK_FAIL(ret < 0 || !index))
		goto end;

	index = 0;
	ret = bpf_tc_act_replace(fd, &opts, &index);
	if (CHECK_FAIL(ret < 0 || !index))
		goto end;

	opts.index = 1;
	ret = bpf_tc_act_attach(fd, &opts, &index);
	if (CHECK_FAIL(!ret || ret != -EEXIST)) {
		ret = -1;
		goto end;
	}

	for (int i = 0; i < 3; i++) {
		memset(&info, 0, sizeof(info));

		ret = bpf_tc_act_get_info(fd, &info);
		if (CHECK_FAIL(ret < 0 && ret != -ESRCH))
			goto end;

		if (CHECK_FAIL(ret == -ESRCH))
			goto end;

		if (CHECK_FAIL(info.refcnt != 1))
			goto end;

		ret = bpf_tc_act_detach(info.index);
		if (CHECK_FAIL(ret < 0))
			goto end;
	}

	CHECK_FAIL(bpf_tc_act_get_info(fd, &info) == -ESRCH);

end:
	ret = bpf_tc_act_detach(0);
	CHECK_FAIL(ret < 0);
	return ret;
}

static int test_tc_act(struct bpf_program *prog)
{
	struct bpf_tc_act_info info = {};
	struct bpf_link *link;
	int ret;
	DECLARE_LIBBPF_OPTS(bpf_tc_act_opts, opts, .index = 42);

	link = bpf_program__attach_tc_act(prog, &opts);
	if (CHECK_FAIL(IS_ERR_OR_NULL(link)))
		return PTR_ERR(link);

	ret = bpf_tc_act_get_info(bpf_program__fd(prog), &info);
	if (CHECK_FAIL(ret < 0))
		goto end;

	if (CHECK_FAIL(info.index != 42))
		goto end;

end:
	ret = bpf_link__destroy(link);
	CHECK_FAIL(ret < 0);
	return ret;
}

void test_test_tc_bpf(void)
{
	const char *file = "./test_tc_bpf_kern.o";
	int cls_fd, act_fd, ret;
	struct bpf_program *clsp, *actp;
	struct bpf_object *obj;

	obj = bpf_object__open(file);
	if (CHECK_FAIL(IS_ERR_OR_NULL(obj)))
		return;

	clsp = bpf_object__find_program_by_title(obj, "classifier");
	if (CHECK_FAIL(IS_ERR_OR_NULL(clsp)))
		goto end;

	actp = bpf_object__find_program_by_title(obj, "action");
	if (CHECK_FAIL(IS_ERR_OR_NULL(clsp)))
		goto end;

	ret = bpf_object__load(obj);
	if (CHECK_FAIL(ret < 0))
		goto end;

	cls_fd = bpf_program__fd(clsp);
	act_fd = bpf_program__fd(actp);

	if (CHECK_FAIL(system("tc qdisc add dev lo clsact")))
		goto end;

	ret = test_tc_cls_internal(cls_fd, BPF_TC_CLSACT_INGRESS);
	if (CHECK_FAIL(ret < 0))
		goto end;

	ret = test_tc_cls(clsp, BPF_TC_CLSACT_EGRESS);
	if (CHECK_FAIL(ret < 0))
		goto end;

	system("tc qdisc del dev lo clsact");

	ret = test_tc_act_internal(act_fd);
	if (CHECK_FAIL(ret < 0))
		goto end;

	ret = test_tc_act(actp);
	if (CHECK_FAIL(ret < 0))
		goto end;

end:
	bpf_object__close(obj);
	return;
}
