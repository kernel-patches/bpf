// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include <linux/pkt_cls.h>
#include "packet_hash.skel.h"

static unsigned int duration;

static void test_xdp_crc32c(struct packet_hash *skel)
{
	char data[] = "abcdefg";
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &data,
		.data_size_in = sizeof(data)-1, /* omit trailing null char */
		.data_out = &data,
		.data_size_out = sizeof(data),
		.repeat = 1,
	);
	int err;
	__u32 csum;

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.xdp_hash), &topts);
	duration = topts.duration;
	if (CHECK(err || topts.retval != XDP_PASS, "bpf", "err %d errno %d retval %d\n",
		  err, errno, topts.retval))
		return;
	csum = *(__u32 *)data;
	ASSERT_EQ(csum, 0xE627F441, "csum");
}

static void test_xdp_crc32c_frags(struct packet_hash *skel)
{
	char *data = malloc(9000);
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = data,
		.data_size_in = 9000,
		.data_out = data,
		.data_size_out = 9000,
		.repeat = 1,
	);
	int err;
	__u32 csum;

	memset(data, 'a', 9000);
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.xdp_hash), &topts);
	duration = topts.duration;
	if (CHECK(err || topts.retval != XDP_PASS, "bpf", "err %d errno %d retval %d\n",
		  err, errno, topts.retval))
		goto out;
	csum = *(__u32 *)data;
	ASSERT_EQ(csum, 0xcb05ae48, "csum");
out:
	free(data);
}

#define ENOTSUPP	524
static void test_xdp_crc32c_oob(struct packet_hash *skel)
{
	int rets[] = {EINVAL, ENOTSUPP, EFAULT, ERANGE, ERANGE};
	int data[ARRAY_SIZE(rets)+1] = {0};
	char buf[10] = {0};
	int i = 0;
	int err;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &data,
		.data_size_in = sizeof(data)-1, /* omit trailing null char */
		.data_out = &data,
		.data_size_out = sizeof(data),
		.repeat = 1,
	);

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.xdp_hash_oob), &topts);
	duration = topts.duration;
	if (CHECK(err || topts.retval != 0, "bpf", "err %d errno %d retval %d\n",
		  err, errno, topts.retval))
		return;
	for (i = 0; i < ARRAY_SIZE(rets); ++i) {
		snprintf(buf, sizeof(buf), "ret[%d]", i);
		ASSERT_EQ(data[i], -rets[i], buf);
	}
}

static void test_skb_crc32c(struct packet_hash *skel)
{
	const int data_size = 1500;
	char *data = calloc(1, data_size);
	struct __sk_buff skb = { 0 };
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = data,
		.data_size_in = data_size,
		.data_out = data,
		.data_size_out = data_size,
		.ctx_in = &skb,
		.ctx_size_in = sizeof(skb),
	);
	int err;
	__u32 csum;

	memset(data, 'a', data_size);
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.skb_hash), &topts);
	duration = topts.duration;
	if (CHECK(err || topts.retval != TC_ACT_OK, "bpf", "err %d errno %d retval %d\n",
		  err, errno, topts.retval))
		goto out;
	csum = *(__u32 *)data;
	ASSERT_EQ(csum, 0xd98287c1, "csum");
out:
	free(data);
}

static void test_skb_crc32c_oob(struct packet_hash *skel)
{
	int rets[] = {EINVAL, ENOTSUPP, EFAULT, ERANGE, ERANGE};
	const int data_size = 1500;
	int *data = calloc(1, data_size);
	char buf[10] = {0};
	struct __sk_buff skb = { 0 };
	int err, i;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = data,
		.data_size_in = data_size,
		.data_out = data,
		.data_size_out = data_size,
		.ctx_in = &skb,
		.ctx_size_in = sizeof(skb),
	);

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.skb_hash_oob), &topts);
	duration = topts.duration;
	if (CHECK(err || topts.retval != 0, "bpf", "err %d errno %d retval %d\n",
		  err, errno, topts.retval))
		return;
	for (i = 0; i < ARRAY_SIZE(rets); ++i) {
		snprintf(buf, sizeof(buf), "ret[%d]", i);
		ASSERT_EQ(data[i], -rets[i], buf);
	}
}

void test_packet_hash(void)
{
	struct packet_hash *skel;

	skel = packet_hash__open_and_load();
	if (!ASSERT_OK_PTR(skel, "packet_hash__open_and_load"))
		return;

	if (test__start_subtest("xdp_crc32c"))
		test_xdp_crc32c(skel);
	if (test__start_subtest("xdp_crc32c_frags"))
		test_xdp_crc32c_frags(skel);
	if (test__start_subtest("xdp_crc32c_oob"))
		test_xdp_crc32c_oob(skel);
	if (test__start_subtest("skb_crc32c"))
		test_skb_crc32c(skel);
	if (test__start_subtest("skb_crc32c_oob"))
		test_skb_crc32c_oob(skel);

	packet_hash__destroy(skel);
}
