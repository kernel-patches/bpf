// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include "prog_call.skel.h"

static void test_nest_prog_call(int prog_index)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
	);
	int err, idx = 0, prog_fd, map_fd;
	struct prog_call *skel;
	struct bpf_program *prog;

	skel = prog_call__open();
	if (!ASSERT_OK_PTR(skel, "prog_call__open"))
		return;

	switch (prog_index) {
	case 0:
		prog = skel->progs.entry_no_subprog;
		break;
	case 1:
		prog = skel->progs.entry_subprog;
		break;
	case 2:
		prog = skel->progs.entry_callback;
		break;
	}

	bpf_program__set_autoload(prog, true);

	err = prog_call__load(skel);
	if (!ASSERT_OK(err, "prog_call__load"))
		return;

	map_fd = bpf_map__fd(skel->maps.jmp_table);
	prog_fd = bpf_program__fd(prog);
	/* maximum recursion level 4 */
	err = bpf_map_update_elem(map_fd, &idx, &prog_fd, 0);
	if (!ASSERT_OK(err, "bpf_map_update_elem"))
		goto out;

	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(skel->bss->vali, 4, "i");
	ASSERT_EQ(skel->bss->valj, 6, "j");
out:
	prog_call__destroy(skel);
}

static void test_prog_call_with_tailcall(void)
{
	struct prog_call *skel;
	int err;

	skel = prog_call__open();
	if (!ASSERT_OK_PTR(skel, "prog_call__open"))
		return;

	bpf_program__set_autoload(skel->progs.entry_tail_call, true);
	err = prog_call__load(skel);
	if (!ASSERT_ERR(err, "prog_call__load"))
		prog_call__destroy(skel);
}

void test_prog_call(void)
{
	if (test__start_subtest("single_main_prog"))
		test_nest_prog_call(0);
	if (test__start_subtest("sub_prog"))
		test_nest_prog_call(1);
	if (test__start_subtest("callback_fn"))
		test_nest_prog_call(2);
	if (test__start_subtest("with_tailcall"))
		test_prog_call_with_tailcall();
}
