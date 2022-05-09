// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Facebook */

#include <test_progs.h>
#include "dynptr_fail.skel.h"
#include "dynptr_success.skel.h"

static size_t log_buf_sz = 1048576; /* 1 MB */
static char obj_log_buf[1048576];

static struct {
	const char *prog_name;
	const char *expected_err_msg;
} dynptr_tests[] = {
	/* failure cases */
	{"missing_put", "Unreleased reference id=1"},
	{"missing_put_callback", "Unreleased reference id"},
	{"put_nonalloc", "Expected an initialized malloc dynptr as arg #1"},
	{"put_data_slice", "type=dynptr_mem expected=fp"},
	{"put_uninit_dynptr", "arg 1 is an unacquired reference"},
	{"use_after_put", "Expected an initialized dynptr as arg #3"},
	{"alloc_twice", "Arg #3 dynptr has to be an uninitialized dynptr"},
	{"add_dynptr_to_map1", "invalid indirect read from stack"},
	{"add_dynptr_to_map2", "invalid indirect read from stack"},
	{"ringbuf_invalid_access", "invalid mem access 'scalar'"},
	{"ringbuf_invalid_api", "type=dynptr_mem expected=alloc_mem"},
	{"ringbuf_out_of_bounds", "value is outside of the allowed memory range"},
	{"data_slice_out_of_bounds", "value is outside of the allowed memory range"},
	{"data_slice_use_after_put", "invalid mem access 'scalar'"},
	{"invalid_helper1", "invalid indirect read from stack"},
	{"invalid_helper2", "Expected an initialized dynptr as arg #3"},
	{"invalid_write1", "Expected an initialized malloc dynptr as arg #1"},
	{"invalid_write2", "Expected an initialized dynptr as arg #3"},
	{"invalid_write3", "Expected an initialized malloc dynptr as arg #1"},
	{"invalid_write4", "arg 1 is an unacquired reference"},
	{"invalid_read1", "invalid read from stack"},
	{"invalid_read2", "cannot pass in non-zero dynptr offset"},
	{"invalid_read3", "invalid read from stack"},
	{"invalid_offset", "invalid write to stack"},
	{"global", "R3 type=map_value expected=fp"},
	{"put_twice", "arg 1 is an unacquired reference"},
	{"put_twice_callback", "arg 1 is an unacquired reference"},
	{"zero_slice_access", "invalid access to memory, mem_size=0 off=0 size=1"},
	/* success cases */
	{"test_basic", NULL},
	{"test_data_slice", NULL},
	{"test_ringbuf", NULL},
	{"test_alloc_zero_bytes", NULL},
};

static void verify_fail(const char *prog_name, const char *expected_err_msg)
{
	LIBBPF_OPTS(bpf_object_open_opts, opts);
	struct bpf_program *prog;
	struct dynptr_fail *skel;
	int err;

	opts.kernel_log_buf = obj_log_buf;
	opts.kernel_log_size = log_buf_sz;
	opts.kernel_log_level = 1;

	skel = dynptr_fail__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "dynptr_fail__open_opts"))
		goto cleanup;

	prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	if (!ASSERT_OK_PTR(prog, "bpf_object__find_program_by_name"))
		goto cleanup;

	bpf_program__set_autoload(prog, true);

	bpf_map__set_max_entries(skel->maps.ringbuf, getpagesize());

	err = dynptr_fail__load(skel);
	if (!ASSERT_ERR(err, "unexpected load success"))
		goto cleanup;

	if (!ASSERT_OK_PTR(strstr(obj_log_buf, expected_err_msg), "expected_err_msg")) {
		fprintf(stderr, "Expected err_msg: %s\n", expected_err_msg);
		fprintf(stderr, "Verifier output: %s\n", obj_log_buf);
	}

cleanup:
	dynptr_fail__destroy(skel);
}

static void verify_success(const char *prog_name)
{
	struct dynptr_success *skel;
	struct bpf_program *prog;
	struct bpf_link *link;

	skel = dynptr_success__open();
	if (!ASSERT_OK_PTR(skel, "dynptr_success__open"))
		return;

	skel->bss->pid = getpid();

	bpf_map__set_max_entries(skel->maps.ringbuf, getpagesize());

	dynptr_success__load(skel);
	if (!ASSERT_OK_PTR(skel, "dynptr_success__load"))
		goto cleanup;

	prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	if (!ASSERT_OK_PTR(prog, "bpf_object__find_program_by_name"))
		goto cleanup;

	link = bpf_program__attach(prog);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach"))
		goto cleanup;

	usleep(1);

	ASSERT_EQ(skel->bss->err, 0, "err");

	bpf_link__destroy(link);

cleanup:
	dynptr_success__destroy(skel);
}

void test_dynptr(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(dynptr_tests); i++) {
		if (!test__start_subtest(dynptr_tests[i].prog_name))
			continue;

		if (dynptr_tests[i].expected_err_msg)
			verify_fail(dynptr_tests[i].prog_name, dynptr_tests[i].expected_err_msg);
		else
			verify_success(dynptr_tests[i].prog_name);
	}
}
