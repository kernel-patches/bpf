// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>

void test_xdp_traits(void)
{
	const char *file = "./test_xdp_traits.bpf.o";
	struct bpf_object *obj;
	struct bpf_program *prog;
	int err, prog_fd;
	struct bpf_test_run_opts topts;

	err = bpf_prog_test_load(file, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
	if (!ASSERT_OK(err, "test_xdp_traits"))
		return;

	bpf_object__for_each_program(prog, obj) {
		if (test__start_subtest(bpf_program__name(prog))) {
			LIBBPF_OPTS_RESET(topts,
				.data_in = &pkt_v4,
				.data_size_in = sizeof(pkt_v4),
				.repeat = 1,
			);

			prog_fd = bpf_program__fd(prog);
			err = bpf_prog_test_run_opts(prog_fd, &topts);
			ASSERT_OK(err, "prog_run");
			ASSERT_EQ(topts.retval, XDP_PASS, "retval");
		}
	}

	bpf_object__close(obj);
}
