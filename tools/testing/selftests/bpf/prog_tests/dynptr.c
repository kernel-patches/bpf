// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Facebook */

#include <test_progs.h>
#include "dynptr_fail.skel.h"
#include "dynptr_success.skel.h"

size_t log_buf_sz = 1024 * 1024;

enum fail_case {
	MISSING_FREE,
	MISSING_FREE_CALLBACK,
	INVALID_FREE1,
	INVALID_FREE2,
	USE_AFTER_FREE,
	MALLOC_TWICE,
	INVALID_MAP_CALL1,
	INVALID_MAP_CALL2,
	RINGBUF_INVALID_ACCESS,
	RINGBUF_INVALID_API,
	RINGBUF_OUT_OF_BOUNDS,
	DATA_SLICE_OUT_OF_BOUNDS,
	DATA_SLICE_USE_AFTER_FREE,
	INVALID_HELPER1,
	INVALID_HELPER2,
	INVALID_WRITE1,
	INVALID_WRITE2,
	INVALID_WRITE3,
	INVALID_WRITE4,
	INVALID_READ1,
	INVALID_READ2,
	INVALID_READ3,
	INVALID_OFFSET,
	GLOBAL,
	FREE_TWICE,
	FREE_TWICE_CALLBACK,
};

static void verify_fail(enum fail_case fail, char *obj_log_buf,  char *err_msg)
{
	LIBBPF_OPTS(bpf_object_open_opts, opts);
	struct bpf_program *prog;
	struct dynptr_fail *skel;
	int err;

	opts.kernel_log_buf = obj_log_buf;
	opts.kernel_log_size = log_buf_sz;
	opts.kernel_log_level = 1;

	skel = dynptr_fail__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	bpf_object__for_each_program(prog, skel->obj)
		bpf_program__set_autoload(prog, false);

	/* these programs should all be rejected by the verifier */
	switch (fail) {
	case MISSING_FREE:
		prog = skel->progs.missing_free;
		break;
	case MISSING_FREE_CALLBACK:
		prog = skel->progs.missing_free_callback;
		break;
	case INVALID_FREE1:
		prog = skel->progs.invalid_free1;
		break;
	case INVALID_FREE2:
		prog = skel->progs.invalid_free2;
		break;
	case USE_AFTER_FREE:
		prog = skel->progs.use_after_free;
		break;
	case MALLOC_TWICE:
		prog = skel->progs.malloc_twice;
		break;
	case INVALID_MAP_CALL1:
		prog = skel->progs.invalid_map_call1;
		break;
	case INVALID_MAP_CALL2:
		prog = skel->progs.invalid_map_call2;
		break;
	case RINGBUF_INVALID_ACCESS:
		prog = skel->progs.ringbuf_invalid_access;
		break;
	case RINGBUF_INVALID_API:
		prog = skel->progs.ringbuf_invalid_api;
		break;
	case RINGBUF_OUT_OF_BOUNDS:
		prog = skel->progs.ringbuf_out_of_bounds;
		break;
	case DATA_SLICE_OUT_OF_BOUNDS:
		prog = skel->progs.data_slice_out_of_bounds;
		break;
	case DATA_SLICE_USE_AFTER_FREE:
		prog = skel->progs.data_slice_use_after_free;
		break;
	case INVALID_HELPER1:
		prog = skel->progs.invalid_helper1;
		break;
	case INVALID_HELPER2:
		prog = skel->progs.invalid_helper2;
		break;
	case INVALID_WRITE1:
		prog = skel->progs.invalid_write1;
		break;
	case INVALID_WRITE2:
		prog = skel->progs.invalid_write2;
		break;
	case INVALID_WRITE3:
		prog = skel->progs.invalid_write3;
		break;
	case INVALID_WRITE4:
		prog = skel->progs.invalid_write4;
		break;
	case INVALID_READ1:
		prog = skel->progs.invalid_read1;
		break;
	case INVALID_READ2:
		prog = skel->progs.invalid_read2;
		break;
	case INVALID_READ3:
		prog = skel->progs.invalid_read3;
		break;
	case INVALID_OFFSET:
		prog = skel->progs.invalid_offset;
		break;
	case GLOBAL:
		prog = skel->progs.global;
		break;
	case FREE_TWICE:
		prog = skel->progs.free_twice;
		break;
	case FREE_TWICE_CALLBACK:
		prog = skel->progs.free_twice_callback;
		break;
	default:
		fprintf(stderr, "unknown fail_case\n");
		return;
	}

	bpf_program__set_autoload(prog, true);

	err = dynptr_fail__load(skel);

	ASSERT_OK_PTR(strstr(obj_log_buf, err_msg), "err_msg not found");

	ASSERT_ERR(err, "unexpected load success");

	dynptr_fail__destroy(skel);
}

static void run_prog(struct dynptr_success *skel, struct bpf_program *prog)
{
	struct bpf_link *link;

	link = bpf_program__attach(prog);
	if (!ASSERT_OK_PTR(link, "bpf program attach"))
		return;

	usleep(1);

	ASSERT_EQ(skel->bss->err, 0, "err");

	bpf_link__destroy(link);
}

static void verify_success(void)
{
	struct dynptr_success *skel;

	skel = dynptr_success__open();

	skel->bss->pid = getpid();

	dynptr_success__load(skel);
	if (!ASSERT_OK_PTR(skel, "dynptr__open_and_load"))
		return;

	run_prog(skel, skel->progs.prog_success);
	run_prog(skel, skel->progs.prog_success_data_slice);
	run_prog(skel, skel->progs.prog_success_ringbuf);

	dynptr_success__destroy(skel);
}

void test_dynptr(void)
{
	char *obj_log_buf;

	obj_log_buf = malloc(3 * log_buf_sz);
	if (!ASSERT_OK_PTR(obj_log_buf, "obj_log_buf"))
		return;
	obj_log_buf[0] = '\0';

	if (test__start_subtest("missing_free"))
		verify_fail(MISSING_FREE, obj_log_buf,
			    "spi=0 is an unreleased dynptr");

	if (test__start_subtest("missing_free_callback"))
		verify_fail(MISSING_FREE_CALLBACK, obj_log_buf,
			    "spi=0 is an unreleased dynptr");

	if (test__start_subtest("invalid_free1"))
		verify_fail(INVALID_FREE1, obj_log_buf,
			    "arg #1 is an unacquired reference and hence cannot be released");

	if (test__start_subtest("invalid_free2"))
		verify_fail(INVALID_FREE2, obj_log_buf, "type=alloc_mem_or_null expected=fp");

	if (test__start_subtest("use_after_free"))
		verify_fail(USE_AFTER_FREE, obj_log_buf,
			    "Expected an initialized dynptr as arg #3");

	if (test__start_subtest("malloc_twice"))
		verify_fail(MALLOC_TWICE, obj_log_buf,
			    "Arg #2 dynptr cannot be an initialized dynptr");

	if (test__start_subtest("invalid_map_call1"))
		verify_fail(INVALID_MAP_CALL1, obj_log_buf,
			    "invalid indirect read from stack");

	if (test__start_subtest("invalid_map_call2"))
		verify_fail(INVALID_MAP_CALL2, obj_log_buf,
			    "invalid indirect read from stack");

	if (test__start_subtest("invalid_helper1"))
		verify_fail(INVALID_HELPER1, obj_log_buf,
			    "invalid indirect read from stack");

	if (test__start_subtest("ringbuf_invalid_access"))
		verify_fail(RINGBUF_INVALID_ACCESS, obj_log_buf,
			    "invalid mem access 'scalar'");

	if (test__start_subtest("ringbuf_invalid_api"))
		verify_fail(RINGBUF_INVALID_API, obj_log_buf,
			    "func bpf_ringbuf_submit#132 reference has not been acquired before");

	if (test__start_subtest("ringbuf_out_of_bounds"))
		verify_fail(RINGBUF_OUT_OF_BOUNDS, obj_log_buf,
			    "value is outside of the allowed memory range");

	if (test__start_subtest("data_slice_out_of_bounds"))
		verify_fail(DATA_SLICE_OUT_OF_BOUNDS, obj_log_buf,
			    "value is outside of the allowed memory range");

	if (test__start_subtest("data_slice_use_after_free"))
		verify_fail(DATA_SLICE_USE_AFTER_FREE, obj_log_buf,
			    "invalid mem access 'scalar'");

	if (test__start_subtest("invalid_helper2"))
		verify_fail(INVALID_HELPER2, obj_log_buf,
			    "Expected an initialized dynptr as arg #3");

	if (test__start_subtest("invalid_write1"))
		verify_fail(INVALID_WRITE1, obj_log_buf,
			    "direct write into dynptr is not permitted");

	if (test__start_subtest("invalid_write2"))
		verify_fail(INVALID_WRITE2, obj_log_buf,
			    "direct write into dynptr is not permitted");

	if (test__start_subtest("invalid_write3"))
		verify_fail(INVALID_WRITE3, obj_log_buf,
			    "direct write into dynptr is not permitted");

	if (test__start_subtest("invalid_write4"))
		verify_fail(INVALID_WRITE4, obj_log_buf,
			    "direct write into dynptr is not permitted");

	if (test__start_subtest("invalid_read1"))
		verify_fail(INVALID_READ1, obj_log_buf,
			    "invalid read from stack");

	if (test__start_subtest("invalid_read2"))
		verify_fail(INVALID_READ2, obj_log_buf,
			    "Expected an initialized dynptr as arg #3");

	if (test__start_subtest("invalid_read3"))
		verify_fail(INVALID_READ3, obj_log_buf,
			    "invalid read from stack");

	if (test__start_subtest("invalid_offset"))
		verify_fail(INVALID_OFFSET, obj_log_buf,
			    "invalid indirect access to stack");

	if (test__start_subtest("global"))
		verify_fail(GLOBAL, obj_log_buf,
			    "R2 type=map_value expected=fp");

	if (test__start_subtest("free_twice"))
		verify_fail(FREE_TWICE, obj_log_buf,
			    "arg #1 is an unacquired reference and hence cannot be released");

	if (test__start_subtest("free_twice_callback"))
		verify_fail(FREE_TWICE_CALLBACK, obj_log_buf,
			    "arg #1 is an unacquired reference and hence cannot be released");

	if (test__start_subtest("success"))
		verify_success();

	free(obj_log_buf);
}
