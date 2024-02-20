// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Bytedance. */

#include <test_progs.h>
#include "tracing_multi_test.skel.h"

struct test_item {
	char *prog;
	char *target;
	int attach_type;
	bool success;
	int link_fd;
};

static struct test_item test_items[] = {
	{
		.prog = "fentry_test1", .target = "bpf_testmod_test_struct_arg_9",
		.attach_type = BPF_TRACE_FENTRY, .success = true,
	},
	{
		.prog = "fentry_test1", .target = "bpf_testmod_test_struct_arg_1",
		.attach_type = BPF_TRACE_FENTRY, .success = false,
	},
	{
		.prog = "fentry_test1", .target = "bpf_testmod_test_struct_arg_2",
		.attach_type = BPF_TRACE_FENTRY, .success = false,
	},
	{
		.prog = "fentry_test1", .target = "bpf_testmod_test_arg_ptr_2",
		.attach_type = BPF_TRACE_FENTRY, .success = false,
	},
	{
		.prog = "fentry_test2", .target = "bpf_testmod_test_struct_arg_2",
		.attach_type = BPF_TRACE_FENTRY, .success = false,
	},
	{
		.prog = "fentry_test2", .target = "bpf_testmod_test_struct_arg_10",
		.attach_type = BPF_TRACE_FENTRY, .success = true,
	},
	{
		.prog = "fentry_test2", .target = "bpf_testmod_test_struct_arg_9",
		.attach_type = BPF_TRACE_FENTRY, .success = false,
	},
	{
		.prog = "fentry_test2", .target = "bpf_testmod_test_arg_ptr_3",
		.attach_type = BPF_TRACE_FENTRY, .success = false,
	},
	{
		.prog = "fentry_test3", .target = "bpf_testmod_test_arg_ptr_3",
		.attach_type = BPF_TRACE_FENTRY, .success = false,
	},
	{
		.prog = "fentry_test3", .target = "bpf_testmod_test_arg_ptr_4",
		.attach_type = BPF_TRACE_FENTRY, .success = true,
	},
	{
		.prog = "fentry_test4", .target = "bpf_testmod_test_struct_arg_4",
		.attach_type = BPF_TRACE_FENTRY, .success = true,
	},
	{
		.prog = "fentry_test4", .target = "bpf_testmod_test_struct_arg_2",
		.attach_type = BPF_TRACE_FENTRY, .success = true,
	},
	{
		.prog = "fentry_test4", .target = "bpf_testmod_test_struct_arg_12",
		.attach_type = BPF_TRACE_FENTRY, .success = false,
	},
	{
		.prog = "fexit_test1", .target = "bpf_testmod_test_struct_arg_2",
		.attach_type = BPF_TRACE_FEXIT, .success = true,
	},
	{
		.prog = "fexit_test1", .target = "bpf_testmod_test_struct_arg_3",
		.attach_type = BPF_TRACE_FEXIT, .success = true,
	},
	{
		.prog = "fexit_test1", .target = "bpf_testmod_test_struct_arg_4",
		.attach_type = BPF_TRACE_FEXIT, .success = false,
	},
	{
		.prog = "fexit_test2", .target = "bpf_testmod_test_struct_arg_10",
		.attach_type = BPF_TRACE_FEXIT, .success = false,
	},
	{
		.prog = "fexit_test2", .target = "bpf_testmod_test_struct_arg_11",
		.attach_type = BPF_TRACE_FEXIT, .success = false,
	},
	{
		.prog = "fexit_test2", .target = "bpf_testmod_test_struct_arg_12",
		.attach_type = BPF_TRACE_FEXIT, .success = true,
	},
	{
		.prog = "fmod_ret_test1", .target = "bpf_modify_return_test2",
		.attach_type = BPF_MODIFY_RETURN, .success = true,
	},
};

static int do_test_item(struct tracing_multi_test *skel, struct test_item *item)
{
	LIBBPF_OPTS(bpf_link_create_opts, link_opts);
	struct bpf_program *prog;
	int err, btf_fd = 0, btf_type_id;

	err = libbpf_find_kernel_btf_id(item->target, item->attach_type,
					&btf_fd, &btf_type_id);
	if (!ASSERT_OK(err, "find_vmlinux_btf_id"))
		return -1;

	link_opts.target_btf_id = btf_type_id;
	prog = bpf_object__find_program_by_name(skel->obj, item->prog);
	if (!ASSERT_OK_PTR(prog, "find_program_by_name"))
		return -1;

	err = bpf_link_create(bpf_program__fd(prog), btf_fd, item->attach_type,
			      &link_opts);
	item->link_fd = err;
	if (item->success) {
		if (!ASSERT_GE(err, 0, "link_create"))
			return -1;
	} else {
		if (!ASSERT_LT(err, 0, "link_create"))
			return -1;
	}

	return 0;
}

void test_tracing_multi_attach(void)
{
	struct tracing_multi_test *skel;
	int i = 0, err, fd;

	skel = tracing_multi_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "tracing_multi_test__open_and_load"))
		return;

	err = tracing_multi_test__attach(skel);
	if (!ASSERT_OK(err, "tracing_multi_test__attach"))
		goto destroy_skel;

	for (; i < ARRAY_SIZE(test_items); i++) {
		if (do_test_item(skel, &test_items[i]))
			break;
	}

	for (i = 0; i < ARRAY_SIZE(test_items); i++) {
		fd = test_items[i].link_fd;
		if (fd >= 0)
			close(fd);
	}

	tracing_multi_test__detach(skel);
destroy_skel:
	tracing_multi_test__destroy(skel);
}
