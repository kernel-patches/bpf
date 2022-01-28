// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2019 Facebook */
#include <test_progs.h>
#include <linux/bpf.h>
#include "bpf/libbpf_internal.h"
#include "test_raw_tp_test_run.skel.h"

void test_raw_tp_test_run(void)
{
	int comm_fd = -1, err, nr_online, i, prog_fd;
	__u64 args[2] = {0x1234ULL, 0x5678ULL};
	int expected_retval = 0x1234 + 0x5678;
	struct test_raw_tp_test_run *skel;
	char buf[] = "new_name";
	bool *online = NULL;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.ctx_in = args,
		.ctx_size_in = sizeof(args),
	);

	err = parse_cpu_mask_file("/sys/devices/system/cpu/online", &online,
				  &nr_online);
	if (CHECK_OPTS(err, "parse_cpu_mask_file", "err %d\n", err))
		return;

	skel = test_raw_tp_test_run__open_and_load();
	if (CHECK_OPTS(!skel, "skel_open", "failed to open skeleton\n"))
		goto cleanup;

	err = test_raw_tp_test_run__attach(skel);
	if (CHECK_OPTS(err, "skel_attach", "skeleton attach failed: %d\n", err))
		goto cleanup;

	comm_fd = open("/proc/self/comm", O_WRONLY|O_TRUNC);
	if (CHECK_OPTS(comm_fd < 0, "open /proc/self/comm", "err %d\n", errno))
		goto cleanup;

	err = write(comm_fd, buf, sizeof(buf));
	CHECK_OPTS(err < 0, "task rename", "err %d", errno);

	CHECK_OPTS(skel->bss->count == 0, "check_count", "didn't increase\n");
	CHECK_OPTS(skel->data->on_cpu != 0xffffffff, "check_on_cpu",
		   "got wrong value\n");

	prog_fd = bpf_program__fd(skel->progs.rename);
	topts.ctx_in = args;
	topts.ctx_size_in = sizeof(__u64);

	err = bpf_prog_test_run_opts(prog_fd, &topts);
	CHECK_OPTS(err == 0, "test_run", "should fail for too small ctx\n");

	topts.ctx_size_in = sizeof(args);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	CHECK_OPTS(err < 0, "test_run", "err %d\n", errno);
	CHECK_OPTS(topts.retval != expected_retval, "check_retval",
		   "expect 0x%x, got 0x%x\n", expected_retval, topts.retval);

	for (i = 0; i < nr_online; i++) {
		if (!online[i])
			continue;

		topts.flags = BPF_F_TEST_RUN_ON_CPU;
		topts.cpu = i;
		topts.retval = 0;
		err = bpf_prog_test_run_opts(prog_fd, &topts);
		CHECK_OPTS(err < 0, "test_run_opts", "err %d\n", errno);
		CHECK_OPTS(skel->data->on_cpu != i, "check_on_cpu",
			   "expect %d got %d\n", i, skel->data->on_cpu);
		CHECK_OPTS(topts.retval != expected_retval, "check_retval",
			   "expect 0x%x, got 0x%x\n", expected_retval,
			   topts.retval);
	}

	/* invalid cpu ID should fail with ENXIO */
	topts.cpu = 0xffffffff;
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	CHECK_OPTS(err >= 0 || errno != ENXIO, "test_run_opts_fail",
		   "should failed with ENXIO\n");

	/* non-zero cpu w/o BPF_F_TEST_RUN_ON_CPU should fail with EINVAL */
	topts.cpu = 1;
	topts.flags = 0;
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	CHECK_OPTS(err >= 0 || errno != EINVAL, "test_run_opts_fail",
		   "should failed with EINVAL\n");

cleanup:
	close(comm_fd);
	test_raw_tp_test_run__destroy(skel);
	free(online);
}
