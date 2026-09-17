// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include "xdp_lru_window.h"
#include "xdp_lru_window.skel.h"

#define SRC_IP		0x0a000001
#define DST_IP		0x0a000002
#define SRC_PORT	12345
#define DST_PORT	80
#define ALT_DST_PORT	81

static struct xdp_lru_window *skel;
static int prog_fd, map_fd;

static void fill_pkt(struct ipv4_packet *pkt, __u16 dport)
{
	*pkt = pkt_v4;
	pkt->iph.saddr = htonl(SRC_IP);
	pkt->iph.daddr = htonl(DST_IP);
	pkt->tcp.source = htons(SRC_PORT);
	pkt->tcp.dest = htons(dport);
}

static void fill_key(struct xdp_lru_window_key *key, __u16 dport)
{
	memset(key, 0, sizeof(*key));
	key->saddr = htonl(SRC_IP);
	key->daddr = htonl(DST_IP);
	key->sport = htons(SRC_PORT);
	key->dport = htons(dport);
	key->proto = IPPROTO_TCP;
}

static int run_pkt(const void *data, __u32 len, int *retval)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = data,
		    .data_size_in = len,
		    .repeat = 1,
	);
	int err;

	err = bpf_prog_test_run_opts(prog_fd, &opts);
	if (!ASSERT_OK(err, "test_run"))
		return err;
	if (retval)
		*retval = opts.retval;
	return 0;
}

static int inject(int n, __u16 dport)
{
	struct ipv4_packet pkt;
	int i, retval;

	fill_pkt(&pkt, dport);
	for (i = 0; i < n; i++) {
		if (run_pkt(&pkt, sizeof(pkt), &retval))
			return -1;
		if (!ASSERT_EQ(retval, XDP_PASS, "retval"))
			return -1;
	}
	return 0;
}

static void reset_map(void)
{
	struct xdp_lru_window_key key, next;
	int err;

	err = bpf_map_get_next_key(map_fd, NULL, &next);
	while (!err) {
		key = next;
		err = bpf_map_get_next_key(map_fd, &key, &next);
		bpf_map_delete_elem(map_fd, &key);
	}
}

static void test_one_and_wrap(void)
{
	struct xdp_lru_window_state st;
	struct xdp_lru_window_key key;
	int i, n;

	reset_map();
	if (inject(1, DST_PORT))
		return;
	fill_key(&key, DST_PORT);
	if (!ASSERT_OK(bpf_map_lookup_elem(map_fd, &key, &st), "lookup"))
		return;
	ASSERT_EQ(st.seq, 1, "seq");
	ASSERT_EQ(st.pkt_len[0], sizeof(struct ipv4_packet), "len0");

	n = AGGREGATION_WINDOW + 5;
	if (inject(n - 1, DST_PORT))
		return;
	if (!ASSERT_OK(bpf_map_lookup_elem(map_fd, &key, &st), "lookup wrap"))
		return;
	ASSERT_EQ(st.seq, n, "seq wrap");
	for (i = 0; i < AGGREGATION_WINDOW; i++)
		ASSERT_EQ(st.pkt_len[i], sizeof(struct ipv4_packet), "slot");
}

static void test_trunc(void)
{
	struct xdp_lru_window_state before, after;
	struct xdp_lru_window_key key, next;
	unsigned char short_pkt[sizeof(struct ethhdr)] = {};
	int err, retval;

	reset_map();
	err = run_pkt(short_pkt, sizeof(short_pkt), &retval);
	if (err)
		return;
	ASSERT_EQ(retval, XDP_PASS, "trunc retval");
	err = bpf_map_get_next_key(map_fd, NULL, &next);
	ASSERT_EQ(err, -ENOENT, "trunc no insert");

	if (inject(1, DST_PORT))
		return;
	fill_key(&key, DST_PORT);
	if (!ASSERT_OK(bpf_map_lookup_elem(map_fd, &key, &before), "setup"))
		return;
	if (run_pkt(short_pkt, sizeof(short_pkt), &retval))
		return;
	ASSERT_EQ(retval, XDP_PASS, "trunc2 retval");
	if (!ASSERT_OK(bpf_map_lookup_elem(map_fd, &key, &after), "after"))
		return;
	ASSERT_EQ(after.seq, before.seq, "trunc no mutate");
}

static void test_isolate(void)
{
	struct xdp_lru_window_state a, b;
	struct xdp_lru_window_key key;

	reset_map();
	if (inject(2, DST_PORT) || inject(1, ALT_DST_PORT))
		return;
	fill_key(&key, DST_PORT);
	if (!ASSERT_OK(bpf_map_lookup_elem(map_fd, &key, &a), "flow a"))
		return;
	fill_key(&key, ALT_DST_PORT);
	if (!ASSERT_OK(bpf_map_lookup_elem(map_fd, &key, &b), "flow b"))
		return;
	ASSERT_EQ(a.seq, 2, "seq a");
	ASSERT_EQ(b.seq, 1, "seq b");
}

void test_xdp_lru_window(void)
{
	skel = xdp_lru_window__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	prog_fd = bpf_program__fd(skel->progs.xdp_lru_window);
	map_fd = bpf_map__fd(skel->maps.flow_table);
	if (!ASSERT_GE(prog_fd, 0, "prog_fd") ||
	    !ASSERT_GE(map_fd, 0, "map_fd"))
		goto out;

	if (test__start_subtest("wrap"))
		test_one_and_wrap();
	if (test__start_subtest("trunc"))
		test_trunc();
	if (test__start_subtest("isolate"))
		test_isolate();
out:
	xdp_lru_window__destroy(skel);
}
