// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>

static void test_xdp_adjust_tail_shrink(void)
{
	const char *file = "./test_xdp_adjust_tail_shrink.o";
	__u32 duration, retval, size, expect_sz;
	struct bpf_object *obj;
	int err, prog_fd;
	char buf[128];

	err = bpf_prog_load(file, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
	if (CHECK_FAIL(err))
		return;

	err = bpf_prog_test_run(prog_fd, 1, &pkt_v4, sizeof(pkt_v4),
				buf, &size, &retval, &duration);

	CHECK(err || retval != XDP_DROP,
	      "ipv4", "err %d errno %d retval %d size %d\n",
	      err, errno, retval, size);

	expect_sz = sizeof(pkt_v6) - 20;  /* Test shrink with 20 bytes */
	err = bpf_prog_test_run(prog_fd, 1, &pkt_v6, sizeof(pkt_v6),
				buf, &size, &retval, &duration);
	CHECK(err || retval != XDP_TX || size != expect_sz,
	      "ipv6", "err %d errno %d retval %d size %d expect-size %d\n",
	      err, errno, retval, size, expect_sz);
	bpf_object__close(obj);
}

static void test_xdp_adjust_tail_grow(void)
{
	const char *file = "./test_xdp_adjust_tail_grow.o";
	struct bpf_object *obj;
	char buf[4096]; /* avoid segfault: large buf to hold grow results */
	__u32 duration, retval, size, expect_sz;
	int err, prog_fd;

	err = bpf_prog_load(file, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
	if (CHECK_FAIL(err))
		return;

	err = bpf_prog_test_run(prog_fd, 1, &pkt_v4, sizeof(pkt_v4),
				buf, &size, &retval, &duration);
	CHECK(err || retval != XDP_DROP,
	      "ipv4", "err %d errno %d retval %d size %d\n",
	      err, errno, retval, size);

	expect_sz = sizeof(pkt_v6) + 40; /* Test grow with 40 bytes */
	err = bpf_prog_test_run(prog_fd, 1, &pkt_v6, sizeof(pkt_v6) /* 74 */,
				buf, &size, &retval, &duration);
	CHECK(err || retval != XDP_TX || size != expect_sz,
	      "ipv6", "err %d errno %d retval %d size %d expect-size %d\n",
	      err, errno, retval, size, expect_sz);

	bpf_object__close(obj);
}

static void test_xdp_adjust_tail_grow2(void)
{
	const char *file = "./test_xdp_adjust_tail_grow.o";
	char buf[4096]; /* avoid segfault: large buf to hold grow results */
	int tailroom = 320; /* SKB_DATA_ALIGN(sizeof(struct skb_shared_info))*/;
	struct bpf_object *obj;
	int err, cnt, i;
	int max_grow;

	struct bpf_prog_test_run_attr tattr = {
		.repeat		= 1,
		.data_in	= &buf,
		.data_out	= &buf,
		.data_size_in	= 0, /* Per test */
		.data_size_out	= 0, /* Per test */
	};

	err = bpf_prog_load(file, BPF_PROG_TYPE_XDP, &obj, &tattr.prog_fd);
	if (CHECK_ATTR(err, "load", "err %d errno %d\n", err, errno))
		return;

	/* Test case-64 */
	memset(buf, 1, sizeof(buf));
	tattr.data_size_in  =  64; /* Determine test case via pkt size */
	tattr.data_size_out = 128; /* Limit copy_size */
	/* Kernel side alloc packet memory area that is zero init */
	err = bpf_prog_test_run_xattr(&tattr);

	CHECK_ATTR(errno != ENOSPC /* Due limit copy_size in bpf_test_finish */
		   || tattr.retval != XDP_TX
		   || tattr.data_size_out != 192, /* Expected grow size */
		   "case-64",
		   "err %d errno %d retval %d size %d\n",
		   err, errno, tattr.retval, tattr.data_size_out);

	/* Extra checks for data contents */
	CHECK_ATTR(tattr.data_size_out != 192
		   || buf[0]   != 1 ||  buf[63]  != 1  /*  0-63  memset to 1 */
		   || buf[64]  != 0 ||  buf[127] != 0  /* 64-127 memset to 0 */
		   || buf[128] != 1 ||  buf[191] != 1, /*128-191 memset to 1 */
		   "case-64-data",
		   "err %d errno %d retval %d size %d\n",
		   err, errno, tattr.retval, tattr.data_size_out);

	/* Test case-128 */
	memset(buf, 2, sizeof(buf));
	tattr.data_size_in  = 128; /* Determine test case via pkt size */
	tattr.data_size_out = sizeof(buf);   /* Copy everything */
	err = bpf_prog_test_run_xattr(&tattr);

	max_grow = 4096 - XDP_PACKET_HEADROOM -	tailroom; /* 3520 */
	CHECK_ATTR(err
		   || tattr.retval != XDP_TX
		   || tattr.data_size_out != max_grow,/* Expect max grow size */
		   "case-128",
		   "err %d errno %d retval %d size %d expect-size %d\n",
		   err, errno, tattr.retval, tattr.data_size_out, max_grow);

	/* Extra checks for data content: Count grow size, will contain zeros */
	for (i = 0, cnt = 0; i < sizeof(buf); i++) {
		if (buf[i] == 0)
			cnt++;
	}
	CHECK_ATTR((cnt != (max_grow - tattr.data_size_in)) /* Grow increase */
		   || tattr.data_size_out != max_grow, /* Total grow size */
		   "case-128-data",
		   "err %d errno %d retval %d size %d grow-size %d\n",
		   err, errno, tattr.retval, tattr.data_size_out, cnt);

	bpf_object__close(obj);
}

void test_xdp_adjust_mb_tail_shrink(void)
{
	const char *file = "./test_xdp_adjust_tail_shrink.o";
	__u32 duration, retval, size, exp_size;
	struct bpf_object *obj;
	int err, prog_fd;
	__u8 *buf;

	/* For the individual test cases, the first byte in the packet
	 * indicates which test will be run.
	 */

	err = bpf_prog_load(file, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
	if (CHECK_FAIL(err))
		return;

	buf = malloc(9000);
	if (CHECK(!buf, "malloc()", "error:%s\n", strerror(errno)))
		return;

	memset(buf, 0, 9000);

	/* Test case removing 10 bytes from last frag, NOT freeing it */
	exp_size = 8990; /* 9000 - 10 */
	err = bpf_prog_test_run(prog_fd, 1, buf, 9000,
				buf, &size, &retval, &duration);

	CHECK(err || retval != XDP_TX || size != exp_size,
	      "9k-10b", "err %d errno %d retval %d[%d] size %d[%u]\n",
	      err, errno, retval, XDP_TX, size, exp_size);

	/* Test case removing one of two pages, assuming 4K pages */
	buf[0] = 1;
	exp_size = 4900; /* 9000 - 4100 */
	err = bpf_prog_test_run(prog_fd, 1, buf, 9000,
				buf, &size, &retval, &duration);

	CHECK(err || retval != XDP_TX || size != exp_size,
	      "9k-1p", "err %d errno %d retval %d[%d] size %d[%u]\n",
	      err, errno, retval, XDP_TX, size, exp_size);

	/* Test case removing two pages resulting in a non mb xdp_buff */
	buf[0] = 2;
	exp_size = 800; /* 9000 - 8200 */
	err = bpf_prog_test_run(prog_fd, 1, buf, 9000,
				buf, &size, &retval, &duration);

	CHECK(err || retval != XDP_TX || size != exp_size,
	      "9k-2p", "err %d errno %d retval %d[%d] size %d[%u]\n",
	      err, errno, retval, XDP_TX, size, exp_size);

	free(buf);

	bpf_object__close(obj);
}

void test_xdp_adjust_mb_tail_grow(void)
{
	const char *file = "./test_xdp_adjust_tail_grow.o";
	__u32 duration, retval, size, exp_size;
	struct bpf_object *obj;
	int err, i, prog_fd;
	__u8 *buf;

	err = bpf_prog_load(file, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
	if (CHECK_FAIL(err))
		return;

	buf = malloc(16384);
	if (CHECK(!buf, "malloc()", "error:%s\n", strerror(errno)))
		return;

	/* Test case add 10 bytes to last frag */
	memset(buf, 1, 16384);
	size = 9000;
	exp_size = size + 10;
	err = bpf_prog_test_run(prog_fd, 1, buf, size,
				buf, &size, &retval, &duration);

	CHECK(err || retval != XDP_TX || size != exp_size,
	      "9k+10b", "err %d retval %d[%d] size %d[%u]\n",
	      err, retval, XDP_TX, size, exp_size);

	for (i = 0; i < 9000; i++)
		CHECK(buf[i] != 1, "9k+10b-old",
		      "Old data not all ok, offset %i is failing [%u]!\n",
		      i, buf[i]);

	for (i = 9000; i < 9010; i++)
		CHECK(buf[i] != 0, "9k+10b-new",
		      "New data not all ok, offset %i is failing [%u]!\n",
		      i, buf[i]);

	for (i = 9010; i < 16384; i++)
		CHECK(buf[i] != 1, "9k+10b-untouched",
		      "Unused data not all ok, offset %i is failing [%u]!\n",
		      i, buf[i]);

	/* Test a too large grow */
	memset(buf, 1, 16384);
	size = 9001;
	exp_size = size;
	err = bpf_prog_test_run(prog_fd, 1, buf, size,
				buf, &size, &retval, &duration);

	CHECK(err || retval != XDP_DROP || size != exp_size,
	      "9k+10b", "err %d retval %d[%d] size %d[%u]\n",
	      err, retval, XDP_TX, size, exp_size);

	free(buf);

	bpf_object__close(obj);
}

void test_xdp_adjust_tail(void)
{
	if (test__start_subtest("xdp_adjust_tail_shrink"))
		test_xdp_adjust_tail_shrink();
	if (test__start_subtest("xdp_adjust_tail_grow"))
		test_xdp_adjust_tail_grow();
	if (test__start_subtest("xdp_adjust_tail_grow2"))
		test_xdp_adjust_tail_grow2();
	if (test__start_subtest("xdp_adjust_mb_tail_shrink"))
		test_xdp_adjust_mb_tail_shrink();
	if (test__start_subtest("xdp_adjust_mb_tail_grow"))
		test_xdp_adjust_mb_tail_grow();
}
