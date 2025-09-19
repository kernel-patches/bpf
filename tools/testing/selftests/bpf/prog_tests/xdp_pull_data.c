// SPDX-License-Identifier: GPL-2.0

#include <bpf/btf.h>
#include <test_progs.h>
#include <network_helpers.h>
#include "test_xdp_pull_data.skel.h"

#define PULL_MAX	(1 << 31)
#define PULL_PLUS_ONE	(1 << 30)

#define XDP_PACKET_HEADROOM 256

int xdpf_sz, sinfo_sz, page_sz;

static bool find_xdp_sizes(void)
{
	struct btf *btf = NULL;
	bool ret = false;
	int id;

	btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(btf, "btf__load_vmlinux_btf"))
		return false;

	id = btf__find_by_name_kind(btf, "xdp_frame", BTF_KIND_STRUCT);
	if (!ASSERT_GT(id, 0, "btf__find_by_name_kind"))
		goto out;

	xdpf_sz = btf__resolve_size(btf, id);

	id = btf__find_by_name_kind(btf, "skb_shared_info", BTF_KIND_STRUCT);
	if (!ASSERT_GT(id, 0, "btf__find_by_name_kind"))
		goto out;

	sinfo_sz = btf__resolve_size(btf, id);
	ret = true;
out:
	btf__free(btf);
	return ret;
}

/* xdp_pull_data_prog will directly read a marker 0xbb stored at buf[1024]
 * so caller expecting XDP_PASS should always pass pull_len no less than 1024
 */
static void run_test(struct test_xdp_pull_data *skel, int retval,
		     int buff_len, int meta_len, int data_len, int pull_len)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct xdp_md ctx = {};
	int prog_fd, err;
	__u8 *buf;

	buf = calloc(buff_len, sizeof(__u8));
	if (!ASSERT_OK_PTR(buf, "calloc buf"))
		return;

	buf[meta_len + 1023] = 0xaa;
	buf[meta_len + 1024] = 0xbb;
	buf[meta_len + 1025] = 0xcc;

	topts.data_in = buf;
	topts.data_out = buf;
	topts.data_size_in = buff_len;
	topts.data_size_out = buff_len;
	ctx.data = meta_len;
	ctx.data_end = meta_len + data_len;
	topts.ctx_in = &ctx;
	topts.ctx_out = &ctx;
	topts.ctx_size_in = sizeof(ctx);
	topts.ctx_size_out = sizeof(ctx);

	skel->bss->data_len = data_len;
	if (pull_len & PULL_MAX) {
		int headroom = XDP_PACKET_HEADROOM - meta_len - xdpf_sz;
		int tailroom = page_sz - XDP_PACKET_HEADROOM -
			       data_len - sinfo_sz;

		pull_len = !!(pull_len & PULL_PLUS_ONE);
		pull_len += headroom + tailroom + data_len;
	}
	skel->bss->pull_len = pull_len;

	prog_fd = bpf_program__fd(skel->progs.xdp_pull_data_prog);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "bpf_prog_test_run_opts");
	ASSERT_EQ(topts.retval, retval, "xdp_pull_data_prog retval");

	if (retval == XDP_DROP)
		goto out;

	ASSERT_EQ(ctx.data_end, meta_len + pull_len, "linear data size");
	ASSERT_EQ(topts.data_size_out, buff_len, "linear + non-linear data size");
	/* Make sure data around xdp->data_end was not messed up by
	 * bpf_xdp_pull_data()
	 */
	ASSERT_EQ(buf[meta_len + 1023], 0xaa, "data[1023]");
	ASSERT_EQ(buf[meta_len + 1024], 0xbb, "data[1024]");
	ASSERT_EQ(buf[meta_len + 1025], 0xcc, "data[1025]");
out:
	free(buf);
}

static void test_xdp_pull_data_basic(void)
{
	struct test_xdp_pull_data *skel;
	u32 max_meta_len, max_data_len;

	skel = test_xdp_pull_data__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_xdp_pull_data__open_and_load"))
		return;

	page_sz = sysconf(_SC_PAGE_SIZE);

	if (!find_xdp_sizes())
		goto out;

	max_meta_len = XDP_PACKET_HEADROOM - xdpf_sz;
	max_data_len = page_sz - XDP_PACKET_HEADROOM - sinfo_sz;

	/* linear xdp pkt, pull 0 byte */
	run_test(skel, XDP_PASS, 2048, 0, 2048, 2048);

	/* multi-buf pkt, pull results in linear xdp pkt */
	run_test(skel, XDP_PASS, 2048, 0, 1024, 2048);

	/* multi-buf pkt, pull 1 byte to linear data area */
	run_test(skel, XDP_PASS, 9000, 0, 1024, 1025);

	/* multi-buf pkt, pull 0 byte to linear data area */
	run_test(skel, XDP_PASS, 9000, 0, 1025, 1025);

	/* multi-buf pkt, empty linear data area, pull requires memmove */
	run_test(skel, XDP_PASS, 9000, 0, 0, PULL_MAX);

	/* multi-buf pkt, no headroom */
	run_test(skel, XDP_PASS, 9000, max_meta_len, 1024, PULL_MAX);

	/* multi-buf pkt, no tailroom, pull requires memmove */
	run_test(skel, XDP_PASS, 9000, 0, max_data_len, PULL_MAX);

	/* Test cases with invalid pull length */

	/* linear xdp pkt, pull more than total data len */
	run_test(skel, XDP_DROP, 2048, 0, 2048, 2049);

	/* multi-buf pkt with no space left in linear data area */
	run_test(skel, XDP_DROP, 9000, max_meta_len, max_data_len,
		 PULL_MAX | PULL_PLUS_ONE);

	/* multi-buf pkt, empty linear data area */
	run_test(skel, XDP_DROP, 9000, 0, 0, PULL_MAX | PULL_PLUS_ONE);

	/* multi-buf pkt, no headroom */
	run_test(skel, XDP_DROP, 9000, max_meta_len, 1024,
		 PULL_MAX | PULL_PLUS_ONE);

	/* multi-buf pkt, no tailroom */
	run_test(skel, XDP_DROP, 9000, 0, max_data_len,
		 PULL_MAX | PULL_PLUS_ONE);

out:
	test_xdp_pull_data__destroy(skel);
}

void test_xdp_pull_data(void)
{
	if (test__start_subtest("xdp_pull_data"))
		test_xdp_pull_data_basic();
}
