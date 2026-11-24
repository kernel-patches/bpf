// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include <linux/if_link.h>
#include <net/if.h>
#include "xdp_dummy.skel.h"
#include "test_xdp_adjust_frags_tail_grow_lo.skel.h"

static void test_xdp_adjust_tail_shrink(void)
{
	const char *file = "./test_xdp_adjust_tail_shrink.bpf.o";
	__u32 expect_sz;
	struct bpf_object *obj;
	int err, prog_fd;
	char buf[128];
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.data_out = buf,
		.data_size_out = sizeof(buf),
		.repeat = 1,
	);

	err = bpf_prog_test_load(file, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
	if (!ASSERT_OK(err, "test_xdp_adjust_tail_shrink"))
		return;

	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "ipv4");
	ASSERT_EQ(topts.retval, XDP_DROP, "ipv4 retval");

	expect_sz = sizeof(pkt_v6) - 20;  /* Test shrink with 20 bytes */
	topts.data_in = &pkt_v6;
	topts.data_size_in = sizeof(pkt_v6);
	topts.data_size_out = sizeof(buf);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "ipv6");
	ASSERT_EQ(topts.retval, XDP_TX, "ipv6 retval");
	ASSERT_EQ(topts.data_size_out, expect_sz, "ipv6 size");

	bpf_object__close(obj);
}

static void test_xdp_adjust_tail_grow(bool is_64k_pagesize)
{
	const char *file = "./test_xdp_adjust_tail_grow.bpf.o";
	struct bpf_object *obj;
	char buf[8192]; /* avoid segfault: large buf to hold grow results */
	__u32 expect_sz;
	int err, prog_fd;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_out = buf,
		.data_size_out = sizeof(buf),
		.repeat = 1,
	);

	/* topts.data_size_in as a special signal to bpf prog */
	if (is_64k_pagesize)
		topts.data_size_in = sizeof(pkt_v4) - 1;
	else
		topts.data_size_in = sizeof(pkt_v4);

	err = bpf_prog_test_load(file, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
	if (!ASSERT_OK(err, "test_xdp_adjust_tail_grow"))
		return;

	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "ipv4");
	ASSERT_EQ(topts.retval, XDP_DROP, "ipv4 retval");

	expect_sz = sizeof(pkt_v6) + 40; /* Test grow with 40 bytes */
	topts.data_in = &pkt_v6;
	topts.data_size_in = sizeof(pkt_v6);
	topts.data_size_out = sizeof(buf);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "ipv6");
	ASSERT_EQ(topts.retval, XDP_TX, "ipv6 retval");
	ASSERT_EQ(topts.data_size_out, expect_sz, "ipv6 size");

	bpf_object__close(obj);
}

static void test_xdp_adjust_tail_grow2(void)
{
	const char *file = "./test_xdp_adjust_tail_grow.bpf.o";
	char buf[4096]; /* avoid segfault: large buf to hold grow results */
	struct bpf_object *obj;
	int err, cnt, i;
	int max_grow, prog_fd;
	/* SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) */
#if defined(__s390x__)
	int tailroom = 512;
#elif defined(__powerpc__)
	int tailroom = 384;
#else
	int tailroom = 320;
#endif

	LIBBPF_OPTS(bpf_test_run_opts, tattr,
		.repeat		= 1,
		.data_in	= &buf,
		.data_out	= &buf,
		.data_size_in	= 0, /* Per test */
		.data_size_out	= 0, /* Per test */
	);

	err = bpf_prog_test_load(file, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
	if (!ASSERT_OK(err, "test_xdp_adjust_tail_grow"))
		return;

	/* Test case-64 */
	memset(buf, 1, sizeof(buf));
	tattr.data_size_in  =  64; /* Determine test case via pkt size */
	tattr.data_size_out = 128; /* Limit copy_size */
	/* Kernel side alloc packet memory area that is zero init */
	err = bpf_prog_test_run_opts(prog_fd, &tattr);

	ASSERT_EQ(errno, ENOSPC, "case-64 errno"); /* Due limit copy_size in bpf_test_finish */
	ASSERT_EQ(tattr.retval, XDP_TX, "case-64 retval");
	ASSERT_EQ(tattr.data_size_out, 192, "case-64 data_size_out"); /* Expected grow size */

	/* Extra checks for data contents */
	ASSERT_EQ(buf[0], 1, "case-64-data buf[0]"); /*  0-63  memset to 1 */
	ASSERT_EQ(buf[63], 1, "case-64-data buf[63]");
	ASSERT_EQ(buf[64], 0, "case-64-data buf[64]"); /* 64-127 memset to 0 */
	ASSERT_EQ(buf[127], 0, "case-64-data buf[127]");
	ASSERT_EQ(buf[128], 1, "case-64-data buf[128]"); /* 128-191 memset to 1 */
	ASSERT_EQ(buf[191], 1, "case-64-data buf[191]");

	/* Test case-128 */
	memset(buf, 2, sizeof(buf));
	tattr.data_size_in  = 128; /* Determine test case via pkt size */
	tattr.data_size_out = sizeof(buf);   /* Copy everything */
	err = bpf_prog_test_run_opts(prog_fd, &tattr);

	max_grow = 4096 - XDP_PACKET_HEADROOM -	tailroom; /* 3520 */
	ASSERT_OK(err, "case-128");
	ASSERT_EQ(tattr.retval, XDP_TX, "case-128 retval");
	ASSERT_EQ(tattr.data_size_out, max_grow, "case-128 data_size_out"); /* Expect max grow */

	/* Extra checks for data content: Count grow size, will contain zeros */
	for (i = 0, cnt = 0; i < sizeof(buf); i++) {
		if (buf[i] == 0)
			cnt++;
	}
	ASSERT_EQ(cnt, max_grow - tattr.data_size_in, "case-128-data cnt"); /* Grow increase */
	ASSERT_EQ(tattr.data_size_out, max_grow, "case-128-data data_size_out"); /* Total grow */

	bpf_object__close(obj);
}

static void test_xdp_adjust_frags_tail_shrink(void)
{
	const char *file = "./test_xdp_adjust_tail_shrink.bpf.o";
	__u32 exp_size;
	struct bpf_program *prog;
	struct bpf_object *obj;
	int err, prog_fd;
	__u8 *buf;
	LIBBPF_OPTS(bpf_test_run_opts, topts);

	/* For the individual test cases, the first byte in the packet
	 * indicates which test will be run.
	 */
	obj = bpf_object__open(file);
	if (libbpf_get_error(obj))
		return;

	prog = bpf_object__next_program(obj, NULL);
	if (bpf_object__load(obj))
		return;

	prog_fd = bpf_program__fd(prog);

	buf = malloc(9000);
	if (!ASSERT_OK_PTR(buf, "alloc buf 9Kb"))
		goto out;

	memset(buf, 0, 9000);

	/* Test case removing 10 bytes from last frag, NOT freeing it */
	exp_size = 8990; /* 9000 - 10 */
	topts.data_in = buf;
	topts.data_out = buf;
	topts.data_size_in = 9000;
	topts.data_size_out = 9000;
	err = bpf_prog_test_run_opts(prog_fd, &topts);

	ASSERT_OK(err, "9Kb-10b");
	ASSERT_EQ(topts.retval, XDP_TX, "9Kb-10b retval");
	ASSERT_EQ(topts.data_size_out, exp_size, "9Kb-10b size");

	/* Test case removing one of two pages, assuming 4K pages */
	buf[0] = 1;
	exp_size = 4900; /* 9000 - 4100 */

	topts.data_size_out = 9000; /* reset from previous invocation */
	err = bpf_prog_test_run_opts(prog_fd, &topts);

	ASSERT_OK(err, "9Kb-4Kb");
	ASSERT_EQ(topts.retval, XDP_TX, "9Kb-4Kb retval");
	ASSERT_EQ(topts.data_size_out, exp_size, "9Kb-4Kb size");

	/* Test case removing two pages resulting in a linear xdp_buff */
	buf[0] = 2;
	exp_size = 800; /* 9000 - 8200 */
	topts.data_size_out = 9000; /* reset from previous invocation */
	err = bpf_prog_test_run_opts(prog_fd, &topts);

	ASSERT_OK(err, "9Kb-9Kb");
	ASSERT_EQ(topts.retval, XDP_TX, "9Kb-9Kb retval");
	ASSERT_EQ(topts.data_size_out, exp_size, "9Kb-9Kb size");

	free(buf);
out:
	bpf_object__close(obj);
}

static void test_xdp_adjust_frags_tail_grow_4k(void)
{
	const char *file = "./test_xdp_adjust_tail_grow.bpf.o";
	__u32 exp_size;
	struct bpf_program *prog;
	struct bpf_object *obj;
	int err, i, prog_fd;
	__u8 *buf;
	LIBBPF_OPTS(bpf_test_run_opts, topts);

	obj = bpf_object__open(file);
	if (libbpf_get_error(obj))
		return;

	prog = bpf_object__next_program(obj, NULL);
	if (bpf_object__load(obj))
		goto out;

	prog_fd = bpf_program__fd(prog);

	buf = malloc(16384);
	if (!ASSERT_OK_PTR(buf, "alloc buf 16Kb"))
		goto out;

	/* Test case add 10 bytes to last frag */
	memset(buf, 1, 16384);
	exp_size = 9000 + 10;

	topts.data_in = buf;
	topts.data_out = buf;
	topts.data_size_in = 9000;
	topts.data_size_out = 16384;
	err = bpf_prog_test_run_opts(prog_fd, &topts);

	ASSERT_OK(err, "9Kb+10b");
	ASSERT_EQ(topts.retval, XDP_TX, "9Kb+10b retval");
	ASSERT_EQ(topts.data_size_out, exp_size, "9Kb+10b size");

	for (i = 0; i < 9000; i++) {
		if (buf[i] != 1)
			ASSERT_EQ(buf[i], 1, "9Kb+10b-old");
	}

	for (i = 9000; i < 9010; i++) {
		if (buf[i] != 0)
			ASSERT_EQ(buf[i], 0, "9Kb+10b-new");
	}

	for (i = 9010; i < 16384; i++) {
		if (buf[i] != 1)
			ASSERT_EQ(buf[i], 1, "9Kb+10b-untouched");
	}

	/* Test a too large grow */
	memset(buf, 1, 16384);
	exp_size = 9001;

	topts.data_in = topts.data_out = buf;
	topts.data_size_in = 9001;
	topts.data_size_out = 16384;
	err = bpf_prog_test_run_opts(prog_fd, &topts);

	ASSERT_OK(err, "9Kb+10b");
	ASSERT_EQ(topts.retval, XDP_DROP, "9Kb+10b retval");
	ASSERT_EQ(topts.data_size_out, exp_size, "9Kb+10b size");

	free(buf);
out:
	bpf_object__close(obj);
}

static void test_xdp_adjust_frags_tail_grow_64k(void)
{
	const char *file = "./test_xdp_adjust_tail_grow.bpf.o";
	__u32 exp_size;
	struct bpf_program *prog;
	struct bpf_object *obj;
	int err, i, prog_fd;
	__u8 *buf;
	LIBBPF_OPTS(bpf_test_run_opts, topts);

	obj = bpf_object__open(file);
	if (libbpf_get_error(obj))
		return;

	prog = bpf_object__next_program(obj, NULL);
	if (bpf_object__load(obj))
		goto out;

	prog_fd = bpf_program__fd(prog);

	buf = malloc(262144);
	if (!ASSERT_OK_PTR(buf, "alloc buf 256Kb"))
		goto out;

	/* Test case add 10 bytes to last frag */
	memset(buf, 1, 262144);
	exp_size = 90000 + 10;

	topts.data_in = buf;
	topts.data_out = buf;
	topts.data_size_in = 90000;
	topts.data_size_out = 262144;
	err = bpf_prog_test_run_opts(prog_fd, &topts);

	ASSERT_OK(err, "90Kb+10b");
	ASSERT_EQ(topts.retval, XDP_TX, "90Kb+10b retval");
	ASSERT_EQ(topts.data_size_out, exp_size, "90Kb+10b size");

	for (i = 0; i < 90000; i++) {
		if (buf[i] != 1)
			ASSERT_EQ(buf[i], 1, "90Kb+10b-old");
	}

	for (i = 90000; i < 90010; i++) {
		if (buf[i] != 0)
			ASSERT_EQ(buf[i], 0, "90Kb+10b-new");
	}

	for (i = 90010; i < 262144; i++) {
		if (buf[i] != 1)
			ASSERT_EQ(buf[i], 1, "90Kb+10b-untouched");
	}

	/* Test a too large grow */
	memset(buf, 1, 262144);
	exp_size = 90001;

	topts.data_in = topts.data_out = buf;
	topts.data_size_in = 90001;
	topts.data_size_out = 262144;
	err = bpf_prog_test_run_opts(prog_fd, &topts);

	ASSERT_OK(err, "90Kb+10b");
	ASSERT_EQ(topts.retval, XDP_DROP, "90Kb+10b retval");
	ASSERT_EQ(topts.data_size_out, exp_size, "90Kb+10b size");

	free(buf);
out:
	bpf_object__close(obj);
}

/*
 * bpf_prog_test_run_xdp() runs on the rxq of lo's queue 0, where generic
 * XDP sets the mem type of the frags it hands to its program. Let generic
 * XDP see a packet on lo first, then free test_run frags from the program.
 */
static void test_xdp_adjust_frags_tail_shrink_after_generic(void)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(9),
	};
	struct netns_obj *ns = NULL;
	struct xdp_dummy *skel;
	int fd = -1, lo, prog_fd;

	skel = xdp_dummy__open_and_load();
	if (!ASSERT_OK_PTR(skel, "xdp_dummy__open_and_load"))
		return;

	ns = netns_new("xdp_adjust_tail_ns", true);
	if (!ASSERT_OK_PTR(ns, "netns_new"))
		goto out;

	SYS(out, "ip link set dev lo up");
	lo = if_nametoindex("lo");
	if (!ASSERT_GT(lo, 0, "lo ifindex"))
		goto out;

	prog_fd = bpf_program__fd(skel->progs.xdp_dummy_prog);
	if (!ASSERT_OK(bpf_xdp_attach(lo, prog_fd, XDP_FLAGS_SKB_MODE, NULL),
		       "attach generic XDP"))
		goto out;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ASSERT_GE(fd, 0, "socket"))
		ASSERT_EQ(sendto(fd, "x", 1, 0, (struct sockaddr *)&addr,
				 sizeof(addr)), 1, "sendto");
	bpf_xdp_detach(lo, XDP_FLAGS_SKB_MODE, NULL);

	test_xdp_adjust_frags_tail_shrink();
out:
	if (fd >= 0)
		close(fd);
	netns_free(ns);
	xdp_dummy__destroy(skel);
}

/*
 * test_run allocates PAGE_SIZE frags, so a program may grow the last one up
 * to the end of its page, also when ingress_ifindex picks the rxq info of
 * another device.
 */
static void test_xdp_adjust_frags_tail_grow_ingress_ifindex(void)
{
	const char *file = "./test_xdp_adjust_tail_grow.bpf.o";
	struct xdp_md ctx = { .data_end = 9000 };
	struct netns_obj *ns = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;
	__u8 *buf = NULL;
	int err, ifindex;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.ctx_in = &ctx,
		.ctx_size_in = sizeof(ctx),
	);

	if (getpagesize() != 4096) {
		test__skip();
		return;
	}

	obj = bpf_object__open(file);
	if (!ASSERT_OK_PTR(obj, "open"))
		return;

	prog = bpf_object__next_program(obj, NULL);
	if (!ASSERT_OK(bpf_object__load(obj), "load"))
		goto out;

	ns = netns_new("xdp_adjust_tail_ns", true);
	if (!ASSERT_OK_PTR(ns, "netns_new"))
		goto out;

	SYS(out, "ip link add veth_xat0 type veth peer name veth_xat1");
	ifindex = if_nametoindex("veth_xat0");
	if (!ASSERT_GT(ifindex, 0, "veth ifindex"))
		goto out;
	ctx.ingress_ifindex = ifindex;

	buf = malloc(16384);
	if (!ASSERT_OK_PTR(buf, "alloc buf 16Kb"))
		goto out;
	memset(buf, 1, 16384);

	/* Test case add 10 bytes to last frag */
	topts.data_in = buf;
	topts.data_out = buf;
	topts.data_size_in = 9000;
	topts.data_size_out = 16384;
	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &topts);

	ASSERT_OK(err, "9Kb+10b");
	ASSERT_EQ(topts.retval, XDP_TX, "9Kb+10b retval");
	ASSERT_EQ(topts.data_size_out, 9000 + 10, "9Kb+10b size");
out:
	free(buf);
	netns_free(ns);
	bpf_object__close(obj);
}

/*
 * The frags generic XDP gets from skb_pp_cow_data() can be parts of a
 * page_pool page, so its rxq info must not allow growing them. test_run
 * must not change that for lo.
 */
static void test_xdp_adjust_frags_tail_grow_lo_after_test_run(void)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(9),
	};
	struct test_xdp_adjust_frags_tail_grow_lo *skel;
	struct netns_obj *ns = NULL;
	static char payload[60000];
	int fd = -1, lo, i, len, prog_fd;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);

	/* larger than the head generic XDP copies the packet into */
	len = getpagesize() + 500;
	if (len > (int)sizeof(payload)) {
		test__skip();
		return;
	}

	skel = test_xdp_adjust_frags_tail_grow_lo__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel open_and_load"))
		return;

	ns = netns_new("xdp_adjust_tail_ns", true);
	if (!ASSERT_OK_PTR(ns, "netns_new"))
		goto out;

	SYS(out, "ip link set dev lo up");
	lo = if_nametoindex("lo");
	if (!ASSERT_GT(lo, 0, "lo ifindex"))
		goto out;

	/* a test run in this netns, before generic XDP sees a packet on lo */
	prog_fd = bpf_program__fd(skel->progs.xdp_grow_frags);
	ASSERT_OK(bpf_prog_test_run_opts(prog_fd, &topts), "test_run");

	if (!ASSERT_OK(bpf_xdp_attach(lo, prog_fd, XDP_FLAGS_SKB_MODE, NULL),
		       "attach generic XDP"))
		goto out;

	/*
	 * a linear skb with little headroom: generic XDP copies it into a
	 * page_pool head page and a frag
	 */
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ASSERT_GE(fd, 0, "socket"))
		ASSERT_EQ(sendto(fd, payload, len, 0, (struct sockaddr *)&addr,
				 sizeof(addr)), len, "sendto");
	for (i = 0; i < 100 && skel->data->grow_ret == 1; i++)
		usleep(10000);
	bpf_xdp_detach(lo, XDP_FLAGS_SKB_MODE, NULL);

	ASSERT_EQ(skel->data->grow_ret, -EOPNOTSUPP, "grow frag on lo");
out:
	if (fd >= 0)
		close(fd);
	netns_free(ns);
	test_xdp_adjust_frags_tail_grow_lo__destroy(skel);
}

void test_xdp_adjust_tail(void)
{
	int page_size = getpagesize();

	if (test__start_subtest("xdp_adjust_tail_shrink"))
		test_xdp_adjust_tail_shrink();
	if (test__start_subtest("xdp_adjust_tail_grow"))
		test_xdp_adjust_tail_grow(page_size == 65536);
	if (test__start_subtest("xdp_adjust_tail_grow2"))
		test_xdp_adjust_tail_grow2();
	if (test__start_subtest("xdp_adjust_frags_tail_shrink"))
		test_xdp_adjust_frags_tail_shrink();
	if (test__start_subtest("xdp_adjust_frags_tail_shrink_after_generic"))
		test_xdp_adjust_frags_tail_shrink_after_generic();
	if (test__start_subtest("xdp_adjust_frags_tail_grow")) {
		if (page_size == 65536)
			test_xdp_adjust_frags_tail_grow_64k();
		else
			test_xdp_adjust_frags_tail_grow_4k();
	}
	if (test__start_subtest("xdp_adjust_frags_tail_grow_ingress_ifindex"))
		test_xdp_adjust_frags_tail_grow_ingress_ifindex();
	if (test__start_subtest("xdp_adjust_frags_tail_grow_lo_after_test_run"))
		test_xdp_adjust_frags_tail_grow_lo_after_test_run();
}
