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

/* Like inject(), but sends frames of a chosen on-wire length (>= the
 * TCP/IPv4 headers) so the recorded pkt_len differs from the default.
 */
static int inject_len(int n, __u16 dport, __u32 len)
{
	unsigned char buf[sizeof(struct ipv4_packet) + 64] = {};
	struct ipv4_packet pkt;
	int i, retval;

	fill_pkt(&pkt, dport);
	memcpy(buf, &pkt, sizeof(pkt));
	if (len > sizeof(buf))
		len = sizeof(buf);
	for (i = 0; i < n; i++) {
		if (run_pkt(buf, len, &retval))
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
	__u32 base_len = sizeof(struct ipv4_packet);
	__u32 new_len = base_len + 20;
	int i;

	reset_map();
	if (inject(1, DST_PORT))
		return;
	fill_key(&key, DST_PORT);
	if (!ASSERT_OK(bpf_map_lookup_elem(map_fd, &key, &st), "lookup"))
		return;
	ASSERT_EQ(st.seq, 1, "seq");
	ASSERT_EQ(st.pkt_len[0], base_len, "len0");

	/* Fill the whole window with base-length packets (slots 0..W-1),
	 * then send 5 more of a different length so they wrap into slots
	 * 0..4. Distinct lengths let the checks below catch a wrong, but
	 * still in-range, post-wrap index.
	 */
	if (inject(AGGREGATION_WINDOW - 1, DST_PORT))
		return;
	if (inject_len(5, DST_PORT, new_len))
		return;
	if (!ASSERT_OK(bpf_map_lookup_elem(map_fd, &key, &st), "lookup wrap"))
		return;
	ASSERT_EQ(st.seq, AGGREGATION_WINDOW + 5, "seq wrap");
	for (i = 0; i < 5; i++)
		ASSERT_EQ(st.pkt_len[i], new_len, "wrapped slot");
	for (i = 5; i < AGGREGATION_WINDOW; i++)
		ASSERT_EQ(st.pkt_len[i], base_len, "kept slot");
}

static void test_trunc(void)
{
	struct xdp_lru_window_state before, after;
	struct xdp_lru_window_key key, next;
	struct ipv4_packet pkt;
	__u32 ip_trunc = sizeof(pkt_v4.eth);
	__u32 tcp_trunc = sizeof(pkt_v4.eth) + sizeof(pkt_v4.iph);
	int err, retval;

	fill_pkt(&pkt, DST_PORT);
	reset_map();

	/* Valid Ethernet/IP ethertype, but the IPv4 header is cut off:
	 * exercises the program's IPv4 length check.
	 */
	if (run_pkt(&pkt, ip_trunc, &retval))
		return;
	ASSERT_EQ(retval, XDP_PASS, "ip trunc retval");
	err = bpf_map_get_next_key(map_fd, NULL, &next);
	ASSERT_EQ(err, -ENOENT, "ip trunc no insert");

	/* Full Ethernet + IPv4 header, but the TCP header is cut off:
	 * exercises the program's TCP length check.
	 */
	if (run_pkt(&pkt, tcp_trunc, &retval))
		return;
	ASSERT_EQ(retval, XDP_PASS, "tcp trunc retval");
	err = bpf_map_get_next_key(map_fd, NULL, &next);
	ASSERT_EQ(err, -ENOENT, "tcp trunc no insert");

	/* A truncated packet must not mutate an already-tracked flow. */
	if (inject(1, DST_PORT))
		return;
	fill_key(&key, DST_PORT);
	if (!ASSERT_OK(bpf_map_lookup_elem(map_fd, &key, &before), "setup"))
		return;
	if (run_pkt(&pkt, tcp_trunc, &retval))
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

	if (test__start_subtest("wrap"))
		test_one_and_wrap();
	if (test__start_subtest("trunc"))
		test_trunc();
	if (test__start_subtest("isolate"))
		test_isolate();

	xdp_lru_window__destroy(skel);
}
