// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#include <test_progs.h>

#include "test_log_buf.skel.h"

static size_t libbpf_log_pos;
static char libbpf_log_buf[1024 * 1024];
static bool libbpf_log_error;

static int libbpf_print_cb(enum libbpf_print_level level, const char *fmt, va_list args)
{
	int emitted_cnt;
	size_t left_cnt;

	left_cnt = sizeof(libbpf_log_buf) - libbpf_log_pos;
	emitted_cnt = vsnprintf(libbpf_log_buf + libbpf_log_pos, left_cnt, fmt, args);

	if (emitted_cnt < 0 || emitted_cnt + 1 > left_cnt) {
		libbpf_log_error = true;
		return 0;
	}

	libbpf_log_pos += emitted_cnt;
	return 0;
}

void test_log_buf(void)
{
	libbpf_print_fn_t old_print_cb = libbpf_set_print(libbpf_print_cb);
	LIBBPF_OPTS(bpf_object_open_opts, opts);
	const size_t log_buf_sz = 1024 * 1024;
	struct test_log_buf* skel;
	char *obj_log_buf, *good_log_buf, *bad_log_buf;
	int err;

	obj_log_buf = malloc(3 *log_buf_sz);
	if (!ASSERT_OK_PTR(obj_log_buf, "obj_log_buf"))
		return;

	good_log_buf = obj_log_buf + log_buf_sz;
	bad_log_buf = obj_log_buf + 2 * log_buf_sz;
	obj_log_buf[0] = good_log_buf[0] = bad_log_buf[0] = '\0';

	opts.kernel_log_buf = obj_log_buf;
	opts.kernel_log_size = log_buf_sz;
	opts.kernel_log_level = 4; /* for BTF this will turn into 1 */

	/* In the first round every prog has its own log_buf, so libbpf logs
	 * don't have program failure logs
	 */
	skel = test_log_buf__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	/* set very verbose level for good_prog so we always get detailed logs */
	bpf_program__set_log_buf(skel->progs.good_prog, good_log_buf, log_buf_sz);
	bpf_program__set_log_level(skel->progs.good_prog, 2);

	bpf_program__set_log_buf(skel->progs.bad_prog, bad_log_buf, log_buf_sz);
	/* log_level 0 with custom log_buf means that verbose logs are not
	 * requested if program load is successful, but libbpf should retry
	 * with log_level 1 on error and put program's verbose load log into
	 * custom log_buf
	 */
	bpf_program__set_log_level(skel->progs.bad_prog, 0);

	err = test_log_buf__load(skel);
	if (!ASSERT_ERR(err, "unexpected_load_success"))
		goto cleanup;

	ASSERT_FALSE(libbpf_log_error, "libbpf_log_error");

	/* there should be no prog loading log because we specified per-prog log buf */
	ASSERT_NULL(strstr(libbpf_log_buf, "-- BEGIN PROG LOAD LOG --"), "unexp_libbpf_log");
	ASSERT_OK_PTR(strstr(libbpf_log_buf, "prog 'bad_prog': BPF program load failed"),
		      "libbpf_log_not_empty");
	ASSERT_OK_PTR(strstr(obj_log_buf, "DATASEC license"), "obj_log_not_empty");
	ASSERT_OK_PTR(strstr(good_log_buf, "0: R1=ctx(id=0,off=0,imm=0) R10=fp0"),
		      "good_log_verbose");
	ASSERT_OK_PTR(strstr(bad_log_buf, "invalid access to map value, value_size=16 off=16000 size=4"),
		      "bad_log_not_empty");

	if (env.verbosity > VERBOSE_NONE) {
		printf("LIBBPF LOG:   \n=================\n%s=================\n", libbpf_log_buf);
		printf("OBJ LOG:      \n=================\n%s=================\n", obj_log_buf);
		printf("GOOD_PROG LOG:\n=================\n%s=================\n", good_log_buf);
		printf("BAD_PROG  LOG:\n=================\n%s=================\n", bad_log_buf);
	}

	/* reset everything */
	test_log_buf__destroy(skel);
	obj_log_buf[0] = good_log_buf[0] = bad_log_buf[0] = '\0';
	libbpf_log_buf[0] = '\0';
	libbpf_log_pos = 0;
	libbpf_log_error = false;

	/* In the second round we let bad_prog's failure be logged through print callback */
	opts.kernel_log_buf = NULL; /* let everything through into print callback */
	opts.kernel_log_size = 0;
	opts.kernel_log_level = 1;

	skel = test_log_buf__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	/* set normal verbose level for good_prog to check log_level is taken into account */
	bpf_program__set_log_buf(skel->progs.good_prog, good_log_buf, log_buf_sz);
	bpf_program__set_log_level(skel->progs.good_prog, 1);

	err = test_log_buf__load(skel);
	if (!ASSERT_ERR(err, "unexpected_load_success"))
		goto cleanup;

	ASSERT_FALSE(libbpf_log_error, "libbpf_log_error");

	/* this time prog loading error should be logged through print callback */
	ASSERT_OK_PTR(strstr(libbpf_log_buf, "libbpf: prog 'bad_prog': -- BEGIN PROG LOAD LOG --"),
		      "libbpf_log_correct");
	ASSERT_STREQ(obj_log_buf, "", "obj_log__empty");
	ASSERT_STREQ(good_log_buf, "processed 4 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0\n",
		     "good_log_ok");
	ASSERT_STREQ(bad_log_buf, "", "bad_log_empty");

	if (env.verbosity > VERBOSE_NONE) {
		printf("LIBBPF LOG:   \n=================\n%s=================\n", libbpf_log_buf);
		printf("OBJ LOG:      \n=================\n%s=================\n", obj_log_buf);
		printf("GOOD_PROG LOG:\n=================\n%s=================\n", good_log_buf);
		printf("BAD_PROG  LOG:\n=================\n%s=================\n", bad_log_buf);
	}

cleanup:
	free(obj_log_buf);
	test_log_buf__destroy(skel);
	libbpf_set_print(old_print_cb);
}
