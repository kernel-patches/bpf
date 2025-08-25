// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <network_helpers.h>
#include "test_xdp_pull_data.skel.h"

/* xdp_pull_data_prog will directly read a marker 0xbb stored at buf[1024]
 * so caller expecting XDP_PASS should always pass pull_len no less than 1024
 */
void test_xdp_pull_data_common(struct test_xdp_pull_data *skel,
			       int buf_len, int linear_len,
			       int pull_len, int retval)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct xdp_md ctx = {};
	int prog_fd, err;
	__u8 *buf;

	buf = calloc(buf_len, sizeof(__u8));
	if (!ASSERT_OK_PTR(buf, "calloc buf"))
		return;

	buf[1023] = 0xaa;
	buf[1024] = 0xbb;
	buf[1025] = 0xcc;

	topts.data_in = buf;
	topts.data_out = buf;
	topts.data_size_in = buf_len;
	topts.data_size_out = buf_len;
	ctx.data_end = linear_len;
	topts.ctx_in = &ctx;
	topts.ctx_out = &ctx;
	topts.ctx_size_in = sizeof(ctx);
	topts.ctx_size_out = sizeof(ctx);

	skel->bss->linear_len = linear_len;
	skel->bss->pull_len = pull_len;

	prog_fd = bpf_program__fd(skel->progs.xdp_pull_data_prog);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "bpf_prog_test_run_opts");
	ASSERT_EQ(topts.retval, retval, "xdp_pull_data_prog retval");

	if (retval == XDP_DROP)
		goto out;

	ASSERT_EQ(ctx.data_end, pull_len, "linear data size");
	ASSERT_EQ(topts.data_size_out, buf_len, "linear + non-linear data size");
	/* Make sure data around xdp->data_end was not messed up by
	 * bpf_xdp_pull_data()
	 */
	ASSERT_EQ(buf[1023], 0xaa, "buf[1023]");
	ASSERT_EQ(buf[1024], 0xbb, "buf[1024]");
	ASSERT_EQ(buf[1025], 0xcc, "buf[1025]");
out:
	free(buf);
}

static void test_xdp_pull_data_basic(void)
{
	struct test_xdp_pull_data *skel;
	u32 page_size;

	skel = test_xdp_pull_data__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_xdp_pull_data__open_and_load"))
		return;

	page_size = sysconf(_SC_PAGE_SIZE);

	/* linear xdp pkt, pull 0 byte */
	test_xdp_pull_data_common(skel, 2048, 2048, 2048, XDP_PASS);
	/* multi-buf pkt, pull results in linear xdp pkt */
	test_xdp_pull_data_common(skel, 2048, 1024, 2048, XDP_PASS);
	/* multi-buf pkt, pull 1 byte to linear data area */
	test_xdp_pull_data_common(skel, 9000, 1024, 1025, XDP_PASS);
	/* multi-buf pkt, pull 0 byte to linear data area */
	test_xdp_pull_data_common(skel, 9000, 1025, 1025, XDP_PASS);

	/* linear xdp pkt, pull more than total data len */
	test_xdp_pull_data_common(skel, 2048, 2048, 2049, XDP_DROP);
	/* multi-buf pkt with no space left in linear data area.
	 * Since ctx.data_end (4096) > max_data_sz, bpf_prog_test_run_xdp()
	 * will fill the whole linear data area and put the reset into a
	 * fragment.
	 */
	test_xdp_pull_data_common(skel, page_size, page_size, page_size, XDP_DROP);

	test_xdp_pull_data__destroy(skel);
}

void test_xdp_pull_data(void)
{
	if (test__start_subtest("xdp_pull_data"))
		test_xdp_pull_data_basic();
}
