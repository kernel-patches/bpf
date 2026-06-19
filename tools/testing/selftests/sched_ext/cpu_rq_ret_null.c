// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Nuoqi Gui
 */
#include <bpf/bpf.h>
#include <scx/common.h>
#include "cpu_rq_ret_null.bpf.skel.h"
#include "scx_test.h"

static enum scx_test_status run(void *ctx)
{
	struct cpu_rq_ret_null *skel;
	int err;

	skel = cpu_rq_ret_null__open();
	if (!skel) {
		SCX_ERR("Failed to open skel");
		return SCX_TEST_FAIL;
	}

	err = cpu_rq_ret_null__load(skel);
	cpu_rq_ret_null__destroy(skel);

	if (!err) {
		SCX_ERR("scx_bpf_cpu_rq() direct dereference loaded");
		return SCX_TEST_FAIL;
	}

	return SCX_TEST_PASS;
}

struct scx_test cpu_rq_ret_null = {
	.name = "cpu_rq_ret_null",
	.description = "Verify that scx_bpf_cpu_rq() returns a nullable pointer",
	.run = run,
};

REGISTER_SCX_TEST(&cpu_rq_ret_null)
