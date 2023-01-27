// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Facebook */

#include <test_progs.h>
#include <network_helpers.h>
#include "dynptr_fail.skel.h"
#include "dynptr_success.skel.h"

enum test_setup_type {
	/* no set up is required. the prog will just be loaded */
	SETUP_NONE,
	SETUP_SYSCALL_SLEEP,
	SETUP_SKB_PROG,
};

static struct {
	const char *prog_name;
	enum test_setup_type type;
} dynptr_tests[] = {
	/* success cases */
	{"test_read_write", SETUP_SYSCALL_SLEEP},
	{"test_data_slice", SETUP_SYSCALL_SLEEP},
	{"test_ringbuf", SETUP_SYSCALL_SLEEP},
	{"test_skb_readonly", SETUP_SKB_PROG},
};

static void verify_success(const char *prog_name, enum test_setup_type setup_type)
{
	struct dynptr_success *skel;
	struct bpf_program *prog;
	struct bpf_link *link;

	skel = dynptr_success__open();
	if (!ASSERT_OK_PTR(skel, "dynptr_success__open"))
		return;

	skel->bss->pid = getpid();

	dynptr_success__load(skel);
	if (!ASSERT_OK_PTR(skel, "dynptr_success__load"))
		goto cleanup;

	prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	if (!ASSERT_OK_PTR(prog, "bpf_object__find_program_by_name"))
		goto cleanup;

	switch (setup_type) {
	case SETUP_SYSCALL_SLEEP:
		link = bpf_program__attach(prog);
		if (!ASSERT_OK_PTR(link, "bpf_program__attach"))
			goto cleanup;

		usleep(1);

		bpf_link__destroy(link);
		break;
	case SETUP_SKB_PROG:
	{
		int prog_fd, err;
		char buf[64];

		LIBBPF_OPTS(bpf_test_run_opts, topts,
			    .data_in = &pkt_v4,
			    .data_size_in = sizeof(pkt_v4),
			    .data_out = buf,
			    .data_size_out = sizeof(buf),
			    .repeat = 1,
		);

		prog_fd = bpf_program__fd(prog);
		if (!ASSERT_GE(prog_fd, 0, "prog_fd"))
			goto cleanup;

		err = bpf_prog_test_run_opts(prog_fd, &topts);

		if (!ASSERT_OK(err, "test_run"))
			goto cleanup;

		break;
	}
	case SETUP_NONE:
		ASSERT_EQ(0, 1, "internal error: SETUP_NONE unimplemented");
	}

	ASSERT_EQ(skel->bss->err, 0, "err");

cleanup:
	dynptr_success__destroy(skel);
}

void test_dynptr(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(dynptr_tests); i++) {
		if (!test__start_subtest(dynptr_tests[i].prog_name))
			continue;

		verify_success(dynptr_tests[i].prog_name, dynptr_tests[i].type);
	}

	RUN_TESTS(dynptr_fail);
}
