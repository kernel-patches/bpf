// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Jesper Dangaard Brouer */

#include <linux/if_link.h> /* before test_progs.h, avoid bpf_util.h redefines */

#include <test_progs.h>
#include "test_check_mtu.skel.h"
#include <network_helpers.h>

#include <stdlib.h>
#include <inttypes.h>

#define IFINDEX_LO 1

static __u32 duration; /* Hint: needed for CHECK macro */

static int read_mtu_device_lo(void)
{
	const char *filename = "/sys/devices/virtual/net/lo/mtu";
	char buf[11] = {};
	int value;
	int fd;

	fd = open(filename, 0, O_RDONLY);
	if (fd == -1)
		return -1;

	if (read(fd, buf, sizeof(buf)) == -1)
		return -2;
	close(fd);

	value = strtoimax(buf, NULL, 10);
	if (errno == ERANGE)
		return -3;

	return value;
}

static void test_check_mtu_xdp_attach(struct bpf_program *prog)
{
	int err = 0;
	int fd;

	fd = bpf_program__fd(prog);
	err = bpf_set_link_xdp_fd(IFINDEX_LO, fd, XDP_FLAGS_SKB_MODE);
	if (CHECK(err, "XDP-attach", "failed"))
		return;

	bpf_set_link_xdp_fd(IFINDEX_LO, -1, 0);
}

static void test_check_mtu_run_xdp(struct test_check_mtu *skel,
				   struct bpf_program *prog,
				   __u32 mtu_expect)
{
	const char *prog_name = bpf_program__name(prog);
	int retval_expect = XDP_PASS;
	__u32 mtu_result = 0;
	char buf[256];
	int err;

	struct bpf_prog_test_run_attr tattr = {
		.repeat = 1,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.data_out = buf,
		.data_size_out = sizeof(buf),
		.prog_fd = bpf_program__fd(prog),
	};

	memset(buf, 0, sizeof(buf));

	err = bpf_prog_test_run_xattr(&tattr);
	CHECK_ATTR(err != 0 || errno != 0, "bpf_prog_test_run",
		   "prog_name:%s (err %d errno %d retval %d)\n",
		   prog_name, err, errno, tattr.retval);

        CHECK(tattr.retval != retval_expect, "retval",
	      "progname:%s unexpected retval=%d expected=%d\n",
	      prog_name, tattr.retval, retval_expect);

	/* Extract MTU that BPF-prog got */
	mtu_result = skel->bss->global_bpf_mtu_xdp;
	CHECK(mtu_result != mtu_expect, "MTU-compare-user",
	      "failed (MTU user:%d bpf:%d)", mtu_expect, mtu_result);
}

static void test_check_mtu_xdp(__u32 mtu, __u32 ifindex)
{
	struct test_check_mtu *skel;
	int err;

	skel = test_check_mtu__open();
	if (CHECK(!skel, "skel_open", "failed"))
		return;

	/* Update "constants" in BPF-prog *BEFORE* libbpf load */
	skel->rodata->GLOBAL_USER_MTU = mtu;
	skel->rodata->GLOBAL_USER_IFINDEX = ifindex;

	err = test_check_mtu__load(skel);
	if (CHECK(err, "skel_load", "failed: %d\n", err))
		goto cleanup;

	test_check_mtu_run_xdp(skel, skel->progs.xdp_use_helper, mtu);
	test_check_mtu_run_xdp(skel, skel->progs.xdp_exceed_mtu, mtu);
	test_check_mtu_run_xdp(skel, skel->progs.xdp_minus_delta, mtu);

cleanup:
	test_check_mtu__destroy(skel);
}

static void test_check_mtu_run_tc(struct test_check_mtu *skel,
				  struct bpf_program *prog,
				  __u32 mtu_expect)
{
	const char *prog_name = bpf_program__name(prog);
	int retval_expect = BPF_OK;
	__u32 mtu_result = 0;
	char buf[256];
	int err;

	struct bpf_prog_test_run_attr tattr = {
		.repeat = 1,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.data_out = buf,
		.data_size_out = sizeof(buf),
		.prog_fd = bpf_program__fd(prog),
	};

	memset(buf, 0, sizeof(buf));

	err = bpf_prog_test_run_xattr(&tattr);
	CHECK_ATTR(err != 0 || errno != 0, "bpf_prog_test_run",
		   "prog_name:%s (err %d errno %d retval %d)\n",
		   prog_name, err, errno, tattr.retval);

        CHECK(tattr.retval != retval_expect, "retval",
	      "progname:%s unexpected retval=%d expected=%d\n",
	      prog_name, tattr.retval, retval_expect);

	/* Extract MTU that BPF-prog got */
	mtu_result = skel->bss->global_bpf_mtu_tc;
	CHECK(mtu_result != mtu_expect, "MTU-compare-user",
	      "failed (MTU user:%d bpf:%d)", mtu_expect, mtu_result);
}


static void test_check_mtu_tc(__u32 mtu, __u32 ifindex)
{
	struct test_check_mtu *skel;
	int err;

	skel = test_check_mtu__open();
	if (CHECK(!skel, "skel_open", "failed"))
		return;

	/* Update "constants" in BPF-prog *BEFORE* libbpf load */
	skel->rodata->GLOBAL_USER_MTU = mtu;
	skel->rodata->GLOBAL_USER_IFINDEX = ifindex;

	err = test_check_mtu__load(skel);
	if (CHECK(err, "skel_load", "failed: %d\n", err))
		goto cleanup;

	test_check_mtu_run_tc(skel, skel->progs.tc_use_helper, mtu);
	test_check_mtu_run_tc(skel, skel->progs.tc_exceed_mtu, mtu);
	test_check_mtu_run_tc(skel, skel->progs.tc_exceed_mtu_da, mtu);
	test_check_mtu_run_tc(skel, skel->progs.tc_minus_delta, mtu);
cleanup:
	test_check_mtu__destroy(skel);
}

void test_check_mtu(void)
{
	struct test_check_mtu *skel;
	__u32 mtu_lo;

	skel = test_check_mtu__open_and_load();
	if (CHECK(!skel, "open and load skel", "failed"))
		return; /* Exit if e.g. helper unknown to kernel */

	if (test__start_subtest("bpf_check_mtu XDP-attach"))
		test_check_mtu_xdp_attach(skel->progs.xdp_use_helper_basic);

	test_check_mtu__destroy(skel);

	mtu_lo = read_mtu_device_lo();
	if (CHECK(mtu_lo < 0, "reading MTU value", "failed (err:%d)", mtu_lo))
		return;

	if (test__start_subtest("bpf_check_mtu XDP-run"))
		test_check_mtu_xdp(mtu_lo, 0);

	if (test__start_subtest("bpf_check_mtu XDP-run ifindex-lookup"))
		test_check_mtu_xdp(mtu_lo, IFINDEX_LO);

	if (test__start_subtest("bpf_check_mtu TC-run"))
		test_check_mtu_tc(mtu_lo, 0);

	if (test__start_subtest("bpf_check_mtu TC-run ifindex-lookup"))
		test_check_mtu_tc(mtu_lo, IFINDEX_LO);
}
