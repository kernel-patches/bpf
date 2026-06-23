// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>

#include "test_pkt_access.skel.h"

#define NONLINEAR_PKT_LEN 9000
#define NONLINEAR_LINEAR_DATA_LEN 64
#define SHORT_OUT_LEN 100

static const __u32 duration;

static void check_run_cnt(int prog_fd, __u64 run_cnt)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	int err;

	err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
	if (CHECK(err, "get_prog_info", "failed to get bpf_prog_info for fd %d\n", prog_fd))
		return;

	CHECK(run_cnt != info.run_cnt, "run_cnt",
	      "incorrect number of repetitions, want %llu have %llu\n", run_cnt, info.run_cnt);
}

static void init_pkt(__u8 *pkt, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		pkt[i] = i & 0xff;
}

static void test_skb_nonlinear_data_out_partial(struct test_pkt_access *skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	__u8 pkt[NONLINEAR_PKT_LEN];
	__u8 out[SHORT_OUT_LEN] = {};
	struct __sk_buff skb = {};
	int prog_fd, err;

	init_pkt(pkt, sizeof(pkt));

	skb.data_end = NONLINEAR_LINEAR_DATA_LEN;

	topts.data_in = pkt;
	topts.data_size_in = sizeof(pkt);
	topts.data_out = out;
	topts.data_size_out = sizeof(out);
	topts.ctx_in = &skb;
	topts.ctx_size_in = sizeof(skb);

	prog_fd = bpf_program__fd(skel->progs.tc_pass_prog);
	err = bpf_prog_test_run_opts(prog_fd, &topts);

	ASSERT_EQ(err, -ENOSPC, "skb_partial_err");
	ASSERT_EQ(topts.data_size_out, sizeof(pkt), "skb_partial_size");
	ASSERT_OK(memcmp(out, pkt, sizeof(out)), "skb_partial_data");
}

static void test_xdp_nonlinear_data_out_partial(struct test_pkt_access *skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	__u8 pkt[NONLINEAR_PKT_LEN];
	__u8 out[SHORT_OUT_LEN] = {};
	struct xdp_md ctx = {};
	int prog_fd, err;

	init_pkt(pkt, sizeof(pkt));

	ctx.data = 0;
	ctx.data_end = NONLINEAR_LINEAR_DATA_LEN;

	topts.data_in = pkt;
	topts.data_size_in = sizeof(pkt);
	topts.data_out = out;
	topts.data_size_out = sizeof(out);
	topts.ctx_in = &ctx;
	topts.ctx_size_in = sizeof(ctx);

	prog_fd = bpf_program__fd(skel->progs.xdp_frags_pass_prog);
	err = bpf_prog_test_run_opts(prog_fd, &topts);

	ASSERT_EQ(err, -ENOSPC, "xdp_partial_err");
	ASSERT_EQ(topts.data_size_out, sizeof(pkt), "xdp_partial_size");
	ASSERT_OK(memcmp(out, pkt, sizeof(out)), "xdp_partial_data");
}

void test_prog_run_opts(void)
{
	struct test_pkt_access *skel;
	int err, stats_fd = -1, prog_fd;
	char buf[10] = {};
	__u64 run_cnt = 0;

	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.repeat = 1,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.data_out = buf,
		.data_size_out = 5,
	);

	stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
	if (!ASSERT_GE(stats_fd, 0, "enable_stats good fd"))
		return;

	skel = test_pkt_access__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.test_pkt_access);

	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_EQ(errno, ENOSPC, "test_run errno");
	ASSERT_ERR(err, "test_run");
	ASSERT_OK(topts.retval, "test_run retval");

	ASSERT_EQ(topts.data_size_out, sizeof(pkt_v4), "test_run data_size_out");
	ASSERT_EQ(buf[5], 0, "overflow, BPF_PROG_TEST_RUN ignored size hint");

	run_cnt += topts.repeat;
	check_run_cnt(prog_fd, run_cnt);

	topts.data_out = NULL;
	topts.data_size_out = 0;
	topts.repeat = 2;
	errno = 0;

	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(errno, "run_no_output errno");
	ASSERT_OK(err, "run_no_output err");
	ASSERT_OK(topts.retval, "run_no_output retval");

	run_cnt += topts.repeat;
	check_run_cnt(prog_fd, run_cnt);

	test_skb_nonlinear_data_out_partial(skel);
	test_xdp_nonlinear_data_out_partial(skel);

cleanup:
	if (skel)
		test_pkt_access__destroy(skel);
	if (stats_fd >= 0)
		close(stats_fd);
}
