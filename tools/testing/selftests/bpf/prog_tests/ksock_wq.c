// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Isovalent */

#include <unistd.h>

#include "test_progs.h"
#include "ksock_wq.skel.h"

void test_ksock_wq(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct ksock_wq *skel;
	int err;

	skel = ksock_wq__open_and_load();
	if (!ASSERT_OK_PTR(skel, "ksock_wq open and load"))
		return;

	err = bpf_prog_test_run_opts(
		bpf_program__fd(skel->progs.ksock_wq_start), &opts);
	if (!ASSERT_OK(err, "run ksock_wq_start"))
		goto out;
	if (!ASSERT_OK(opts.retval, "ksock_wq_start retval"))
		goto out;

	while (!__atomic_load_n(&skel->bss->callback_done, __ATOMIC_ACQUIRE))
		usleep(1000);

	ASSERT_EQ(skel->bss->create_err, -EOPNOTSUPP,
		  "workqueue create rejected");

out:
	ksock_wq__destroy(skel);
}
