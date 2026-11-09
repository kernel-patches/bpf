// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "bpf_iter_bpf_map.skel.h"

static void test_iter_link_create_log(int target_fd, struct bpf_link_create_opts *opts,
				      __u64 flags, int err_exp, const char *msg)
{
	struct bpf_iter_bpf_map *skel;
	char log_buf[128] = {};
	int err, fd, prog_fd;
	LIBBPF_OPTS(bpf_log_opts, log_opts,
		.buf = log_buf,
		.size = sizeof(log_buf),
		.level = 1,
	);

	skel = bpf_iter_bpf_map__open();
	if (!ASSERT_OK_PTR(skel, "bpf_iter_bpf_map__open"))
		return;

	err = bpf_program__set_flags(skel->progs.dump_bpf_map, flags);
	if (!ASSERT_OK(err, "bpf_program__set_flags"))
		goto out;

	err = bpf_iter_bpf_map__load(skel);
	if (!ASSERT_OK(err, "bpf_iter_bpf_map__load"))
		goto out;

	opts->log_opts = &log_opts;
	prog_fd = bpf_program__fd(skel->progs.dump_bpf_map);
	fd = bpf_link_create(prog_fd, target_fd, BPF_TRACE_ITER, opts);
	if (!ASSERT_LT(fd, 0, "bpf_link_create")) {
		close(fd);
		goto out;
	}

	ASSERT_EQ(fd, err_exp, "err");
	ASSERT_STREQ(log_buf, msg, "log_buf");
	ASSERT_EQ(log_opts.true_size, strlen(msg) + 1, "log_size");

out:
	bpf_iter_bpf_map__destroy(skel);
}

static void test_log_invalid_target_fd(void)
{
	const char *msg = "Invalid target_fd.\n";
	LIBBPF_OPTS(bpf_link_create_opts, opts);

	test_iter_link_create_log(-1, &opts, 0, -EINVAL, msg);
}

static void test_log_invalid_flags(void)
{
	const char *msg = "Invalid flags.\n";
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .flags = 1,
	);

	test_iter_link_create_log(0, &opts, 0, -EINVAL, msg);
}

static void test_log_iter_info_only(void)
{
	const char *msg = "iter_info and iter_info_len must be both set or both unset.\n";
	union bpf_iter_link_info info = {};
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .iter.info = &info,
	);

	test_iter_link_create_log(0, &opts, 0, -EINVAL, msg);
}

static void test_log_iter_info_len_only(void)
{
	const char *msg = "iter_info and iter_info_len must be both set or both unset.\n";
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .iter.len = sizeof(union bpf_iter_link_info),
	);

	test_iter_link_create_log(0, &opts, 0, -EINVAL, msg);
}

static void test_log_invalid_iter_info(void)
{
	unsigned char info[sizeof(union bpf_iter_link_info) + 1] = {};
	const char *msg = "Invalid iter_info.\n";
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .iter.info = (union bpf_iter_link_info *)info,
		    .iter.len = sizeof(info),
	);

	info[sizeof(info) - 1] = 1;
	test_iter_link_create_log(0, &opts, 0, -E2BIG, msg);
}

static void test_log_invalid_iter_info_len(void)
{
	const char *msg = "Invalid iter_info_len.\n";
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .iter.info = (union bpf_iter_link_info *)1,
		    .iter.len = sizeof(union bpf_iter_link_info),
	);

	test_iter_link_create_log(0, &opts, 0, -EFAULT, msg);
}

static void test_log_invalid_prog(void)
{
	const char *msg = "The iter target does not support the bpf prog.\n";
	LIBBPF_OPTS(bpf_link_create_opts, opts);

	test_iter_link_create_log(0, &opts, BPF_F_SLEEPABLE, -EINVAL, msg);
}

void test_iter_link_log(void)
{
	if (test__start_subtest("invalid_target_fd"))
		test_log_invalid_target_fd();
	if (test__start_subtest("invalid_flags"))
		test_log_invalid_flags();
	if (test__start_subtest("iter_info_only"))
		test_log_iter_info_only();
	if (test__start_subtest("iter_info_len_only"))
		test_log_iter_info_len_only();
	if (test__start_subtest("invalid_iter_info"))
		test_log_invalid_iter_info();
	if (test__start_subtest("invalid_iter_info_len"))
		test_log_invalid_iter_info_len();
	if (test__start_subtest("invalid_prog"))
		test_log_invalid_prog();
}
