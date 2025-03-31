// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include "xdp_dummy.skel.h"

void test_xdp_perf(void)
{
	struct xdp_dummy *skel;
	char in[128], out[128];
	int err, prog_fd;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = in,
		.data_size_in = sizeof(in),
		.data_out = out,
		.data_size_out = sizeof(out),
		.repeat = 1000000,
	);

	skel = xdp_dummy__open_and_load();
	prog_fd = bpf_program__fd(skel->progs.xdp_dummy_prog);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, XDP_PASS, "test_run retval");
	ASSERT_EQ(topts.data_size_out, 128, "test_run data_size_out");

	xdp_dummy__destroy(skel);
}

void test_xdp_adjust_head_perf(void)
{
	struct xdp_dummy *skel;
	int repeat = 9000000;
	struct xdp_md ctx_in;
	char data[100];
	int err, prog_fd;
	size_t test_header_size[] = {
		ETH_ALEN,
		sizeof(struct iphdr),
		sizeof(struct ipv6hdr),
		200,
	};
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, topts,
			    .data_in = &data,
			    .data_size_in = sizeof(data),
			    .repeat = repeat,
	);

	topts.ctx_in = &ctx_in;
	topts.ctx_size_in = sizeof(ctx_in);
	memset(&ctx_in, 0, sizeof(ctx_in));
	ctx_in.data_meta = 0;
	ctx_in.data_end = ctx_in.data + sizeof(data);

	skel = xdp_dummy__open_and_load();
	prog_fd = bpf_program__fd(skel->progs.xdp_dummy_adjust_head);

	for (int i = 0; i < ARRAY_SIZE(test_header_size); i++) {
		skel->bss->head_size = test_header_size[i];
		err = bpf_prog_test_run_opts(prog_fd, &topts);
		ASSERT_OK(err, "test_run");
		ASSERT_EQ(topts.retval, XDP_PASS, "test_run retval");
		fprintf(stdout, "run adjust head with size %zd cost %d ns\n",
			test_header_size[i], topts.duration);
	}
	xdp_dummy__destroy(skel);
}
