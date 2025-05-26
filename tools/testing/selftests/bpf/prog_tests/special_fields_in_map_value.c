// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2025. Huawei Technologies Co., Ltd */
#include <test_progs.h>

#include "special_fields_in_map_value.skel.h"

void test_special_fields_in_map_value(void)
{
	struct special_fields_in_map_value *skel;
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	skel = special_fields_in_map_value__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open()"))
		return;

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.test_special_fields), &opts);
	ASSERT_OK(err, "run");
	ASSERT_EQ(opts.retval, 0, "retval");

	LIBBPF_OPTS_RESET(opts);
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.test_percpu_special_fields),
				     &opts);
	ASSERT_OK(err, "percpu run");
	ASSERT_EQ(opts.retval, 0, "percpu retval");

	LIBBPF_OPTS_RESET(opts);
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.test_local_stor_special_fields),
				     &opts);
	ASSERT_OK(err, "local_stor run");
	ASSERT_EQ(opts.retval, 0, "local_stor retval");

	special_fields_in_map_value__destroy(skel);
}
