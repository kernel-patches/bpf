// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include <net/if.h>
#include "test_xdp.skel.h"
#include "test_xdp_bpf2bpf.skel.h"

struct meta {
	int ifindex;
	int pkt_len;
};

struct test_ctx_s {
	bool passed;
	int pkt_size;
};

struct test_ctx_s test_ctx;

static void on_sample(void *ctx, int cpu, void *data, __u32 size)
{
	struct meta *meta = (struct meta *)data;
	struct ipv4_packet *trace_pkt_v4 = data + sizeof(*meta);
	unsigned char *raw_pkt = data + sizeof(*meta);
	struct test_ctx_s *tst_ctx = ctx;
	int duration = 0;

	if (CHECK(size < sizeof(pkt_v4) + sizeof(*meta),
		  "check_size", "size %u < %zu\n",
		  size, sizeof(pkt_v4) + sizeof(*meta)))
		return;

	if (CHECK(meta->ifindex != if_nametoindex("lo"), "check_meta_ifindex",
		  "meta->ifindex = %d\n", meta->ifindex))
		return;

	if (CHECK(meta->pkt_len != tst_ctx->pkt_size, "check_meta_pkt_len",
		  "meta->pkt_len = %d\n", tst_ctx->pkt_size))
		return;

	if (CHECK(memcmp(trace_pkt_v4, &pkt_v4, sizeof(pkt_v4)),
		  "check_packet_content", "content not the same\n"))
		return;

	if (meta->pkt_len > sizeof(pkt_v4)) {
		for (int i = 0; i < (meta->pkt_len - sizeof(pkt_v4)); i++) {
			if (raw_pkt[i + sizeof(pkt_v4)] != (unsigned char)i) {
				CHECK(true, "check_packet_content",
				      "byte %zu does not match %u != %u\n",
				      i + sizeof(pkt_v4),
				      raw_pkt[i + sizeof(pkt_v4)],
				      (unsigned char)i);
				break;
			}
		}
	}

	tst_ctx->passed = true;
}

#define BUF_SZ	9000

static int run_xdp_bpf2bpf_pkt_size(int pkt_fd, struct perf_buffer *pb,
				    struct test_xdp_bpf2bpf *ftrace_skel,
				    int pkt_size)
{
	__u32 duration = 0, retval, size;
	__u8 *buf, *buf_in;
	int err, ret = 0;

	if (pkt_size > BUF_SZ || pkt_size < sizeof(pkt_v4))
		return -EINVAL;

	buf_in = malloc(BUF_SZ);
	if (CHECK(!buf_in, "buf_in malloc()", "error:%s\n", strerror(errno)))
		return -ENOMEM;

	buf = malloc(BUF_SZ);
	if (CHECK(!buf, "buf malloc()", "error:%s\n", strerror(errno))) {
		ret = -ENOMEM;
		goto free_buf_in;
	}

	test_ctx.passed = false;
	test_ctx.pkt_size = pkt_size;

	memcpy(buf_in, &pkt_v4, sizeof(pkt_v4));
	if (pkt_size > sizeof(pkt_v4)) {
		for (int i = 0; i < (pkt_size - sizeof(pkt_v4)); i++)
			buf_in[i + sizeof(pkt_v4)] = i;
	}

	/* Run test program */
	err = bpf_prog_test_run(pkt_fd, 1, buf_in, pkt_size,
				buf, &size, &retval, &duration);

	if (CHECK(err || retval != XDP_PASS || size != pkt_size,
		  "ipv4", "err %d errno %d retval %d size %d\n",
		  err, errno, retval, size)) {
		ret = err ? err : -EINVAL;
		goto free_buf;
	}

	/* Make sure bpf_xdp_output() was triggered and it sent the expected
	 * data to the perf ring buffer.
	 */
	err = perf_buffer__poll(pb, 100);
	if (CHECK(err <= 0, "perf_buffer__poll", "err %d\n", err)) {
		ret = -EINVAL;
		goto free_buf;
	}

	if (CHECK_FAIL(!test_ctx.passed)) {
		ret = -EINVAL;
		goto free_buf;
	}

	/* Verify test results */
	if (CHECK(ftrace_skel->bss->test_result_fentry != if_nametoindex("lo"),
		  "result", "fentry failed err %llu\n",
		  ftrace_skel->bss->test_result_fentry)) {
		ret = -EINVAL;
		goto free_buf;
	}

	if (CHECK(ftrace_skel->bss->test_result_fexit != XDP_PASS, "result",
		  "fexit failed err %llu\n",
		  ftrace_skel->bss->test_result_fexit))
		ret = -EINVAL;

free_buf:
	free(buf);
free_buf_in:
	free(buf_in);

	return ret;
}

void test_xdp_bpf2bpf(void)
{
	int err, pkt_fd, map_fd;
	__u32 duration = 0;
	int pkt_sizes[] = {sizeof(pkt_v4), 1024, 4100, 8200};
	struct iptnl_info value4 = {.family = AF_INET6};
	struct test_xdp *pkt_skel = NULL;
	struct test_xdp_bpf2bpf *ftrace_skel = NULL;
	struct vip key4 = {.protocol = 6, .family = AF_INET};
	struct bpf_program *prog;
	struct perf_buffer *pb = NULL;
	struct perf_buffer_opts pb_opts = {};

	/* Load XDP program to introspect */
	pkt_skel = test_xdp__open_and_load();
	if (CHECK(!pkt_skel, "pkt_skel_load", "test_xdp skeleton failed\n"))
		return;

	pkt_fd = bpf_program__fd(pkt_skel->progs._xdp_tx_iptunnel);

	map_fd = bpf_map__fd(pkt_skel->maps.vip2tnl);
	bpf_map_update_elem(map_fd, &key4, &value4, 0);

	/* Load trace program */
	ftrace_skel = test_xdp_bpf2bpf__open();
	if (CHECK(!ftrace_skel, "__open", "ftrace skeleton failed\n"))
		goto out;

	/* Demonstrate the bpf_program__set_attach_target() API rather than
	 * the load with options, i.e. opts.attach_prog_fd.
	 */
	prog = ftrace_skel->progs.trace_on_entry;
	bpf_program__set_expected_attach_type(prog, BPF_TRACE_FENTRY);
	bpf_program__set_attach_target(prog, pkt_fd, "_xdp_tx_iptunnel");

	prog = ftrace_skel->progs.trace_on_exit;
	bpf_program__set_expected_attach_type(prog, BPF_TRACE_FEXIT);
	bpf_program__set_attach_target(prog, pkt_fd, "_xdp_tx_iptunnel");

	err = test_xdp_bpf2bpf__load(ftrace_skel);
	if (CHECK(err, "__load", "ftrace skeleton failed\n"))
		goto out;

	err = test_xdp_bpf2bpf__attach(ftrace_skel);
	if (CHECK(err, "ftrace_attach", "ftrace attach failed: %d\n", err))
		goto out;

	/* Set up perf buffer */
	pb_opts.sample_cb = on_sample;
	pb_opts.ctx = &test_ctx;
	pb = perf_buffer__new(bpf_map__fd(ftrace_skel->maps.perf_buf_map),
			      8, &pb_opts);
	if (!ASSERT_OK_PTR(pb, "perf_buf__new"))
		goto out;

	for (int i = 0; i < ARRAY_SIZE(pkt_sizes); i++)
		run_xdp_bpf2bpf_pkt_size(pkt_fd, pb, ftrace_skel,
					 pkt_sizes[i]);
out:
	if (pb)
		perf_buffer__free(pb);
	test_xdp__destroy(pkt_skel);
	test_xdp_bpf2bpf__destroy(ftrace_skel);
}
