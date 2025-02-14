/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2023 David Vernet <dvernet@meta.com>
 * Copyright (c) 2023 Tejun Heo <tj@kernel.org>
 */
#include <bpf/bpf.h>
#include <scx/common.h>
#include <sys/wait.h>
#include <unistd.h>
#include "enq_select_cpu_fails.bpf.skel.h"
#include "scx_test.h"

static enum scx_test_status run(void *ctx)
{
	struct enq_select_cpu_fails *skel;

	skel = enq_select_cpu_fails__open_and_load();
	if (skel) {
		enq_select_cpu_fails__destroy(skel);
		SCX_ERR("This program should fail to load");
		return SCX_TEST_FAIL;
	}

	return SCX_TEST_PASS;
}

struct scx_test enq_select_cpu_fails = {
	.name = "enq_select_cpu_fails",
	.description = "Verify we fail to call scx_bpf_select_cpu_dfl() "
		       "from ops.enqueue()",
	.run = run,
};
REGISTER_SCX_TEST(&enq_select_cpu_fails)
