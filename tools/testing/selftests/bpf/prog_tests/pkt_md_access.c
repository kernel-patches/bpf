// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>

void test_pkt_md_access(void)
{
	const char *file = "./test_pkt_md_access.o";
	struct bpf_object *obj;
	int err, prog_fd;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 10,
	);

	err = bpf_prog_test_load(file, BPF_PROG_TYPE_SCHED_CLS, &obj, &prog_fd);
	if (CHECK_FAIL(err))
		return;

	err = bpf_prog_test_run_opts(prog_fd, &topts);
	CHECK_OPTS(err || topts.retval, "",
		   "err %d errno %d retval %d duration %d\n", err, errno,
		   topts.retval, topts.duration);

	bpf_object__close(obj);
}
