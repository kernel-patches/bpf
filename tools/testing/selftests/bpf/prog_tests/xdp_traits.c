// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>

static void _test_xdp_traits(void)
{
	const char *file = "./test_xdp_traits.bpf.o";
	struct bpf_object *obj;
	int err, prog_fd;
	char buf[128];

	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.data_out = buf,
		.data_size_out = sizeof(buf),
		.repeat = 1,
	);

	err = bpf_prog_test_load(file, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
	if (!ASSERT_OK(err, "test_xdp_traits"))
		return;

	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "prog_run");
	ASSERT_EQ(topts.retval, XDP_PASS, "retval");

	bpf_object__close(obj);
}

void test_xdp_traits(void)
{
	if (test__start_subtest("xdp_traits"))
		_test_xdp_traits();
}
