// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include <net/if.h>
#include <linux/if_link.h>

#include "test_xdp_pifo.skel.h"

#define SYS(fmt, ...)						\
	({							\
		char cmd[1024];					\
		snprintf(cmd, sizeof(cmd), fmt, ##__VA_ARGS__);	\
		if (!ASSERT_OK(system(cmd), cmd))		\
			goto out;				\
	})

static void run_xdp_prog(int prog_fd, void *data, size_t data_size, int repeat)
{
	struct xdp_md ctx_in = {};
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
			    .data_in = data,
			    .data_size_in = data_size,
			    .ctx_in = &ctx_in,
			    .ctx_size_in = sizeof(ctx_in),
			    .repeat = repeat,
			    .flags = BPF_F_TEST_XDP_LIVE_FRAMES,
		);
	int err;

	ctx_in.data_end = ctx_in.data + sizeof(pkt_v4);
	err = bpf_prog_test_run_opts(prog_fd, &opts);
	ASSERT_OK(err, "bpf_prog_test_run(valid)");
}

static void run_dequeue_prog(int prog_fd, int exp_proto)
{
	struct ipv4_packet data_out;
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
			    .data_out = &data_out,
			    .data_size_out = sizeof(data_out),
			    .repeat = 1,
		);
	int err;

	err = bpf_prog_test_run_opts(prog_fd, &opts);
	ASSERT_OK(err, "bpf_prog_test_run(valid)");
	ASSERT_EQ(opts.retval, exp_proto == -1 ? 0 : 1, "valid-retval");
	if (exp_proto >= 0) {
		ASSERT_EQ(opts.data_size_out, sizeof(pkt_v4), "valid-datasize");
		ASSERT_EQ(data_out.eth.h_proto, exp_proto, "valid-pkt");
	} else {
		ASSERT_EQ(opts.data_size_out, 0, "no-pkt-returned");
	}
}

void test_xdp_pifo(void)
{
	int xdp_prog_fd, dequeue_prog_fd, i;
	struct test_xdp_pifo *skel = NULL;
	struct ipv4_packet data;

	skel = test_xdp_pifo__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel"))
		return;

	xdp_prog_fd = bpf_program__fd(skel->progs.xdp_pifo);
	dequeue_prog_fd = bpf_program__fd(skel->progs.dequeue_pifo);
	data = pkt_v4;

	run_xdp_prog(xdp_prog_fd, &data, sizeof(data), 3);

	/* kernel program queues packets with prio 2, 1, 0 (in that order), we
	 * should get back 0 and 1, and 2 should get dropped on dequeue
	 */
	run_dequeue_prog(dequeue_prog_fd, 0);
	run_dequeue_prog(dequeue_prog_fd, 1);
	run_dequeue_prog(dequeue_prog_fd, -1);

	xdp_prog_fd = bpf_program__fd(skel->progs.xdp_pifo_inc);
	run_xdp_prog(xdp_prog_fd, &data, sizeof(data), 1024);

	skel->bss->pkt_count = 0;
	skel->data->prio = 0;
	skel->data->drop_above = 1024;
	for (i = 0; i < 1024; i++)
		run_dequeue_prog(dequeue_prog_fd, i*10);

	test_xdp_pifo__destroy(skel);
}

void test_xdp_pifo_live(void)
{
	struct test_xdp_pifo *skel = NULL;
	int err, ifindex_src, ifindex_dst;
	int xdp_prog_fd, dequeue_prog_fd;
	struct nstoken *nstoken = NULL;
	struct ipv4_packet data;
	struct bpf_link *link;
	__u32 xdp_flags = XDP_FLAGS_DEQUEUE_MODE;
	LIBBPF_OPTS(bpf_xdp_attach_opts, opts,
		    .old_prog_fd = -1);

	skel = test_xdp_pifo__open();
	if (!ASSERT_OK_PTR(skel, "skel"))
		return;

	SYS("ip netns add testns");
	nstoken = open_netns("testns");
	if (!ASSERT_OK_PTR(nstoken, "setns"))
		goto out;

	SYS("ip link add veth_src type veth peer name veth_dst");
	SYS("ip link set dev veth_src up");
	SYS("ip link set dev veth_dst up");

	ifindex_src = if_nametoindex("veth_src");
	ifindex_dst = if_nametoindex("veth_dst");
	if (!ASSERT_NEQ(ifindex_src, 0, "ifindex_src") ||
	    !ASSERT_NEQ(ifindex_dst, 0, "ifindex_dst"))
		goto out;

	skel->bss->tgt_ifindex = ifindex_src;
	skel->data->drop_above = 3;

	err = test_xdp_pifo__load(skel);
	ASSERT_OK(err, "load skel");

	link = bpf_program__attach_xdp(skel->progs.xdp_check_pkt, ifindex_dst);
	if (!ASSERT_OK_PTR(link, "prog_attach"))
		goto out;
	skel->links.xdp_check_pkt = link;

	xdp_prog_fd = bpf_program__fd(skel->progs.xdp_pifo);
	dequeue_prog_fd = bpf_program__fd(skel->progs.dequeue_pifo);
	data = pkt_v4;

	err = bpf_xdp_attach(ifindex_src, dequeue_prog_fd, xdp_flags, &opts);
	if (!ASSERT_OK(err, "attach-dequeue"))
		goto out;

	run_xdp_prog(xdp_prog_fd, &data, sizeof(data), 3);

	/* wait for the packets to be flushed */
	kern_sync_rcu();

	ASSERT_EQ(skel->bss->seen_good_pkts, 3, "live packets OK");

	opts.old_prog_fd = dequeue_prog_fd;
	err = bpf_xdp_attach(ifindex_src, -1, xdp_flags, &opts);
	ASSERT_OK(err, "dequeue-detach");

out:
	test_xdp_pifo__destroy(skel);
}
