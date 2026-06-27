// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpf/bpf.h>
#include "bpf_sdt_observer.skel.h"
#include "bpf_sdt_target.skel.h"

static int sdt_attach(struct bpf_program *obs)
{
	LIBBPF_OPTS(bpf_link_create_opts, opts);

	return bpf_link_create(bpf_program__fd(obs), 0, BPF_TRACE_SDT, &opts);
}

static void read_args(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct bpf_sdt_target *tgt_skel;
	struct bpf_sdt_observer *skel;
	char pkt[64] = {};
	int link, err;

	tgt_skel = bpf_sdt_target__open_and_load();
	if (!ASSERT_OK_PTR(tgt_skel, "target open_and_load"))
		return;

	skel = bpf_sdt_observer__open();
	if (!ASSERT_OK_PTR(skel, "observer open"))
		goto out_tgt;

	bpf_program__set_autoload(skel->progs.tc_trace_prog, false);
	bpf_program__set_autoload(skel->progs.subprog_trace_prog, false);
	bpf_program__set_attach_target(skel->progs.xdp_trace_prog,
				       bpf_program__fd(tgt_skel->progs.xdp_prog),
				       "xdp_probe_len_ret");
	err = bpf_sdt_observer__load(skel);
	if (!ASSERT_OK(err, "observer load"))
		goto out_obs;

	link = sdt_attach(skel->progs.xdp_trace_prog);
	if (!ASSERT_GE(link, 0, "attach xdp_probe_len_ret"))
		goto out_obs;

	topts.data_in = pkt;
	topts.data_size_in = sizeof(pkt);
	topts.data_size_out = sizeof(pkt);
	err = bpf_prog_test_run_opts(bpf_program__fd(tgt_skel->progs.xdp_prog), &topts);
	if (!ASSERT_OK(err, "prog_test_run"))
		goto out_link;

	ASSERT_EQ(skel->bss->xdp_len, sizeof(pkt), "xdp_len");
	ASSERT_EQ(skel->bss->xdp_ret, XDP_PASS, "xdp_ret");

out_link:
	close(link);
out_obs:
	bpf_sdt_observer__destroy(skel);
out_tgt:
	bpf_sdt_target__destroy(tgt_skel);
}

static void multi_prog(void)
{
	struct bpf_sdt_target *tgt_skel;
	struct bpf_sdt_observer *skel;
	int link1, link2, err;

	tgt_skel = bpf_sdt_target__open_and_load();
	if (!ASSERT_OK_PTR(tgt_skel, "target open_and_load"))
		return;

	skel = bpf_sdt_observer__open();
	if (!ASSERT_OK_PTR(skel, "observer open"))
		goto out_tgt;

	bpf_program__set_autoload(skel->progs.subprog_trace_prog, false);
	bpf_program__set_attach_target(skel->progs.xdp_trace_prog,
				       bpf_program__fd(tgt_skel->progs.xdp_prog),
				       "xdp_probe_len_ret");
	bpf_program__set_attach_target(skel->progs.tc_trace_prog,
				       bpf_program__fd(tgt_skel->progs.tc_prog),
				       "tc_probe");
	err = bpf_sdt_observer__load(skel);
	if (!ASSERT_OK(err, "observer load"))
		goto out_obs;

	link1 = sdt_attach(skel->progs.xdp_trace_prog);
	ASSERT_GE(link1, 0, "attach xdp xdp_probe_len_ret");

	link2 = sdt_attach(skel->progs.tc_trace_prog);
	ASSERT_GE(link2, 0, "attach tc_probe");

	close(link1);
	close(link2);
out_obs:
	bpf_sdt_observer__destroy(skel);
out_tgt:
	bpf_sdt_target__destroy(tgt_skel);
}

static void subprog_probe(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct bpf_sdt_target *tgt_skel;
	struct bpf_sdt_observer *skel;
	char pkt[64] = {0, 1, 2, 3};
	int link, err;

	tgt_skel = bpf_sdt_target__open_and_load();
	if (!ASSERT_OK_PTR(tgt_skel, "target open_and_load"))
		return;

	skel = bpf_sdt_observer__open();
	if (!ASSERT_OK_PTR(skel, "observer open"))
		goto out_tgt;

	bpf_program__set_autoload(skel->progs.tc_trace_prog, false);
	bpf_program__set_autoload(skel->progs.xdp_trace_prog, false);
	bpf_program__set_attach_target(skel->progs.subprog_trace_prog,
				       bpf_program__fd(tgt_skel->progs.xdp_prog),
				       "xdp_probe_ctx");
	err = bpf_sdt_observer__load(skel);
	if (!ASSERT_OK(err, "observer load"))
		goto out_obs;

	link = sdt_attach(skel->progs.subprog_trace_prog);
	if (!ASSERT_GE(link, 0, "attach xdp_probe_ctx"))
		goto out_obs;

	topts.data_in = pkt;
	topts.data_size_in = sizeof(pkt);
	topts.data_size_out = sizeof(pkt);
	err = bpf_prog_test_run_opts(bpf_program__fd(tgt_skel->progs.xdp_prog), &topts);
	ASSERT_OK(err, "prog_test_run");
	ASSERT_EQ(skel->bss->xdp_len, sizeof(pkt), "xdp_len");

	close(link);
out_obs:
	bpf_sdt_observer__destroy(skel);
out_tgt:
	bpf_sdt_target__destroy(tgt_skel);
}

void test_bpf_sdt(void)
{
	if (test__start_subtest("read_args"))
		read_args();
	if (test__start_subtest("multi_prog"))
		multi_prog();
	if (test__start_subtest("subprog_probe"))
		subprog_probe();
}
