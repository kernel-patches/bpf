// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include "test_xdp_context_test_run.skel.h"

void test_xdp_context_test_run(void)
{
	struct test_xdp_context_test_run *skel = NULL;
	char data[sizeof(pkt_v4) + sizeof(__u32)];
	char buf[128];
	char bad_ctx[sizeof(struct xdp_md)];
	struct xdp_md ctx_in, ctx_out;
	struct bpf_test_run_opts tattr = {
		.sz = sizeof(struct bpf_test_run_opts),
		.data_in = &data,
		.data_out = buf,
		.data_size_in = sizeof(data),
		.data_size_out = sizeof(buf),
		.ctx_out = &ctx_out,
		.ctx_size_out = sizeof(ctx_out),
		.repeat = 1,
	};
	int err, prog_fd;


	skel = test_xdp_context_test_run__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel"))
		return;
	prog_fd = bpf_program__fd(skel->progs._xdp_context);

	*(__u32 *)data = XDP_PASS;
	*(struct ipv4_packet *)(data + sizeof(__u32)) = pkt_v4;

	memset(&ctx_in, 0, sizeof(ctx_in));
	tattr.ctx_in = &ctx_in;
	tattr.ctx_size_in = sizeof(ctx_in);

	tattr.ctx_in = &ctx_in;
	tattr.ctx_size_in = sizeof(ctx_in);
	ctx_in.data_meta = 0;
	ctx_in.data = sizeof(__u32);
	ctx_in.data_end = ctx_in.data + sizeof(pkt_v4);
	err = bpf_prog_test_run_opts(prog_fd, &tattr);
	ASSERT_OK(err, "bpf_prog_test_run(test1)");
	ASSERT_EQ(tattr.retval, XDP_PASS, "test1-retval");
	ASSERT_EQ(tattr.data_size_out, sizeof(pkt_v4), "test1-datasize");
	ASSERT_EQ(tattr.ctx_size_out, tattr.ctx_size_in, "test1-ctxsize");
	ASSERT_EQ(ctx_out.data_meta, 0, "test1-datameta");
	ASSERT_EQ(ctx_out.data, ctx_out.data_meta, "test1-data");
	ASSERT_EQ(ctx_out.data_end, sizeof(pkt_v4), "test1-dataend");

	/* Data past the end of the kernel's struct xdp_md must be 0 */
	bad_ctx[sizeof(bad_ctx) - 1] = 1;
	tattr.ctx_in = bad_ctx;
	tattr.ctx_size_in = sizeof(bad_ctx);
	err = bpf_prog_test_run_opts(prog_fd, &tattr);
	ASSERT_ERR(err, "bpf_prog_test_run(test2)");
	ASSERT_EQ(errno, 22, "test2-errno");

	/* The egress cannot be specified */
	ctx_in.egress_ifindex = 1;
	err = bpf_prog_test_run_opts(prog_fd, &tattr);
	ASSERT_ERR(err, "bpf_prog_test_run(test3)");
	ASSERT_EQ(errno, 22, "test3-errno");

	/* data_meta must reference the start of data */
	ctx_in.data_meta = sizeof(__u32);
	ctx_in.data = ctx_in.data_meta;
	ctx_in.data_end = ctx_in.data + sizeof(pkt_v4);
	ctx_in.egress_ifindex = 0;
	err = bpf_prog_test_run_opts(prog_fd, &tattr);
	ASSERT_ERR(err, "bpf_prog_test_run(test4)");
	ASSERT_EQ(errno, 22, "test4-errno");

	/* Metadata must be 32 bytes or smaller */
	ctx_in.data_meta = 0;
	ctx_in.data = sizeof(__u32)*9;
	ctx_in.data_end = ctx_in.data + sizeof(pkt_v4);
	err = bpf_prog_test_run_opts(prog_fd, &tattr);
	ASSERT_ERR(err, "bpf_prog_test_run(test5)");
	ASSERT_EQ(errno, 22, "test5-errno");

	/* Metadata's size must be a multiple of 4 */
	ctx_in.data = 3;
	err = bpf_prog_test_run_opts(prog_fd, &tattr);
	ASSERT_ERR(err, "bpf_prog_test_run(test6)");
	ASSERT_EQ(errno, 22, "test6-errno");

	/* Total size of data must match data_end - data_meta */
	ctx_in.data = 0;
	ctx_in.data_end = sizeof(pkt_v4) - 4;
	err = bpf_prog_test_run_opts(prog_fd, &tattr);
	ASSERT_ERR(err, "bpf_prog_test_run(test7)");
	ASSERT_EQ(errno, 22, "test7-errno");

	ctx_in.data_end = sizeof(pkt_v4) + 4;
	err = bpf_prog_test_run_opts(prog_fd, &tattr);
	ASSERT_ERR(err, "bpf_prog_test_run(test8)");
	ASSERT_EQ(errno, 22, "test8-errno");

	/* RX queue cannot be specified without specifying an ingress */
	ctx_in.data_end = sizeof(pkt_v4);
	ctx_in.ingress_ifindex = 0;
	ctx_in.rx_queue_index = 1;
	err = bpf_prog_test_run_opts(prog_fd, &tattr);
	ASSERT_ERR(err, "bpf_prog_test_run(test9)");
	ASSERT_EQ(errno, 22, "test9-errno");

	ctx_in.ingress_ifindex = 1;
	ctx_in.rx_queue_index = 1;
	err = bpf_prog_test_run_opts(prog_fd, &tattr);
	ASSERT_ERR(err, "bpf_prog_test_run(test10)");
	ASSERT_EQ(errno, 22, "test10-errno");

	test_xdp_context_test_run__destroy(skel);
}
