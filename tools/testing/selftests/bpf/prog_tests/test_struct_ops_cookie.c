// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>

#include "struct_ops_cookie.skel.h"

static void test_struct_ops_cookie_basic(void)
{
	LIBBPF_OPTS(bpf_struct_ops_opts, attach_opts);
	LIBBPF_OPTS(bpf_test_run_opts, run_opts);
	struct struct_ops_cookie *skel;
	struct bpf_link *link;
	int err, prog_fd;

	skel = struct_ops_cookie__open_and_load();
	if (!ASSERT_OK_PTR(skel, "struct_ops_cookie__open_and_load"))
		return;

	attach_opts.cookie = 0x12345678;
	link = bpf_map__attach_struct_ops_opts(skel->maps.testmod_cookie, &attach_opts);
	if (!ASSERT_OK_PTR(link, "bpf_map__attach_struct_ops_opts"))
		goto out;

	prog_fd = bpf_program__fd(skel->progs.trigger_test_1);
	err = bpf_prog_test_run_opts(prog_fd, &run_opts);
	ASSERT_OK(err, "bpf_prog_test_run_opts");
	ASSERT_EQ(skel->bss->cookie_test_1, 0x12345678, "cookie_1_value");

	prog_fd = bpf_program__fd(skel->progs.trigger_test_2);
	err = bpf_prog_test_run_opts(prog_fd, &run_opts);
	ASSERT_OK(err, "bpf_prog_test_run_opts");
	ASSERT_EQ(skel->bss->cookie_test_2, 0x12345678, "cookie_2_value");

out:
	bpf_link__destroy(link);
	struct_ops_cookie__destroy(skel);
}

void serial_test_struct_ops_cookie(void)
{
	if (test__start_subtest("struct_ops_cookie_basic"))
		test_struct_ops_cookie_basic();
}
