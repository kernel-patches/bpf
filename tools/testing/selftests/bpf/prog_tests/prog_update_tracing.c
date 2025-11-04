// SPDX-License-Identifier: GPL-2.0

#include <network_helpers.h>
#include <test_progs.h>
#include "prog_update_tracing.skel.h"
#include "test_pkt_access.skel.h"

static bool assert_program_order(struct prog_update_tracing *skel_trace,
				 struct test_pkt_access *skel_pkt,
				 const struct prog_update_tracing__bss *expected)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts_trace);
	LIBBPF_OPTS(bpf_test_run_opts, topts_skb,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	int prog_fd;

	prog_fd = bpf_program__fd(skel_trace->progs.fmod_ret1);
	if (!ASSERT_OK(bpf_prog_test_run_opts(prog_fd, &topts_trace),
		       "bpf_prog_test_run trace"))
		return false;

	if (!ASSERT_EQ(skel_trace->bss->fentry1_seq,
		       expected->fentry1_seq, "fentry1_seq"))
		return false;
	if (!ASSERT_EQ(skel_trace->bss->fentry1_cookie,
		       expected->fentry1_cookie, "fentry1_cookie"))
		return false;
	if (!ASSERT_EQ(skel_trace->bss->fentry2_seq,
		       expected->fentry2_seq, "fentry2_seq"))
		return false;
	if (!ASSERT_EQ(skel_trace->bss->fentry2_cookie,
		       expected->fentry2_cookie, "fentry2_cookie"))
		return false;
	if (!ASSERT_EQ(skel_trace->bss->fmod_ret1_seq,
		       expected->fmod_ret1_seq, "fmod_ret1_seq"))
		return false;
	if (!ASSERT_EQ(skel_trace->bss->fmod_ret1_cookie,
		       expected->fmod_ret1_cookie, "fmod_ret1_cookie"))
		return false;
	if (!ASSERT_EQ(skel_trace->bss->fmod_ret2_seq,
		       expected->fmod_ret2_seq, "fmod_ret2_seq"))
		return false;
	if (!ASSERT_EQ(skel_trace->bss->fmod_ret2_cookie,
		       expected->fmod_ret2_cookie, "fmod_ret2_cookie"))
		return false;
	if (!ASSERT_EQ(skel_trace->bss->fexit1_seq,
		       expected->fexit1_seq, "fexit1_seq"))
		return false;
	if (!ASSERT_EQ(skel_trace->bss->fexit1_cookie,
		       expected->fexit1_cookie, "fexit1_cookie"))
		return false;
	if (!ASSERT_EQ(skel_trace->bss->fexit2_seq,
		       expected->fexit2_seq, "fexit2_seq"))
		return false;
	if (!ASSERT_EQ(skel_trace->bss->fexit2_cookie,
		       expected->fexit2_cookie, "fexit2_cookie"))
		return false;
	if (!ASSERT_EQ(skel_trace->bss->sequence, expected->sequence,
		       "sequence"))
		return false;
	if (!ASSERT_EQ(skel_trace->bss->sequence_bpf, 0, "sequence_bpf"))
		return false;

	prog_fd = bpf_program__fd(skel_pkt->progs.test_pkt_access);
	if (!ASSERT_OK(bpf_prog_test_run_opts(prog_fd, &topts_skb),
		       "bpf_prog_test_run skb"))
		return false;

	if (!ASSERT_EQ(skel_trace->bss->sequence, expected->sequence,
		       "sequence"))
		return false;
	if (!ASSERT_EQ(skel_trace->bss->fentry1_bpf_seq,
		       expected->fentry1_bpf_seq, "fentry1_bpf_seq"))
		return false;
	if (!ASSERT_EQ(skel_trace->bss->fentry1_bpf_cookie,
		       expected->fentry1_bpf_cookie, "fentry1_bpf_cookie"))
		return false;
	if (!ASSERT_EQ(skel_trace->bss->fentry2_bpf_seq,
		       expected->fentry2_bpf_seq, "fentry2_bpf_seq"))
		return false;
	if (!ASSERT_EQ(skel_trace->bss->fentry2_bpf_cookie,
		       expected->fentry2_bpf_cookie, "fentry2_bpf_cookie"))
		return false;
	if (!ASSERT_EQ(skel_trace->bss->freplace1_bpf_seq,
		       expected->freplace1_bpf_seq, "freplace1_bpf_seq"))
		return false;
	if (!ASSERT_EQ(skel_trace->bss->freplace2_bpf_seq,
		       expected->freplace2_bpf_seq, "freplace2_bpf_seq"))
		return false;
	if (!ASSERT_EQ(skel_trace->bss->fexit1_bpf_seq,
		       expected->fexit1_bpf_seq, "fexit1_bpf_seq"))
		return false;
	if (!ASSERT_EQ(skel_trace->bss->fexit1_bpf_cookie,
		       expected->fexit1_bpf_cookie, "fexit1_bpf_cookie"))
		return false;
	if (!ASSERT_EQ(skel_trace->bss->fexit2_bpf_seq,
		       expected->fexit2_bpf_seq, "fexit2_bpf_seq"))
		return false;
	if (!ASSERT_EQ(skel_trace->bss->fexit2_bpf_cookie,
		       expected->fexit2_bpf_cookie, "fexit2_bpf_cookie"))
		return false;
	if (!ASSERT_EQ(skel_trace->bss->sequence_bpf, expected->sequence_bpf,
		       "sequence_bpf"))
		return false;

	memset(skel_trace->bss, 0, sizeof(*skel_trace->bss));

	return true;
}

void test_prog_update_tracing(void)
{
	const struct prog_update_tracing__bss expected_inverted = {
		.fentry1_seq = 2,
		.fentry1_cookie = 102,
		.fentry2_seq = 1,
		.fentry2_cookie = 101,
		.fmod_ret1_seq = 4,
		.fmod_ret1_cookie = 104,
		.fmod_ret2_seq = 3,
		.fmod_ret2_cookie = 103,
		.fexit1_seq = 6,
		.fexit1_cookie = 106,
		.fexit2_seq = 5,
		.fexit2_cookie = 105,
		.sequence = 6,
		.fentry1_bpf_seq = 2,
		.fentry1_bpf_cookie = 202,
		.fentry2_bpf_seq = 1,
		.fentry2_bpf_cookie = 201,
		.freplace1_bpf_seq = 3,
		.freplace2_bpf_seq = 0,
		.fexit1_bpf_seq = 5,
		.fexit1_bpf_cookie = 205,
		.fexit2_bpf_seq = 4,
		.fexit2_bpf_cookie = 204,
		.sequence_bpf = 5,
	};
	const struct prog_update_tracing__bss expected_normal = {
		.fentry1_seq = 1,
		.fentry1_cookie = 101,
		.fentry2_seq = 2,
		.fentry2_cookie = 102,
		.fmod_ret1_seq = 3,
		.fmod_ret1_cookie = 103,
		.fmod_ret2_seq = 4,
		.fmod_ret2_cookie = 104,
		.fexit1_seq = 5,
		.fexit1_cookie = 105,
		.fexit2_seq = 6,
		.fexit2_cookie = 106,
		.sequence = 6,
		.fentry1_bpf_seq = 1,
		.fentry1_bpf_cookie = 201,
		.fentry2_bpf_seq = 2,
		.fentry2_bpf_cookie = 202,
		.freplace1_bpf_seq = 3,
		.freplace2_bpf_seq = 0,
		.fexit1_bpf_seq = 4,
		.fexit1_bpf_cookie = 204,
		.fexit2_bpf_seq = 5,
		.fexit2_bpf_cookie = 205,
		.sequence_bpf = 5,
	};
	LIBBPF_OPTS(bpf_link_update_opts, update_opts);
	LIBBPF_OPTS(bpf_trace_opts, trace_opts);
	struct prog_update_tracing *skel_trace1 = NULL;
	struct prog_update_tracing *skel_trace2 = NULL;
	struct test_pkt_access *skel_pkt1 = NULL;
	struct test_pkt_access *skel_pkt2 = NULL;
	int link_fd, prog_fd, err;
	struct bpf_link *link;

	skel_trace1 = prog_update_tracing__open();
	if (!ASSERT_OK_PTR(skel_trace1, "skel_trace1"))
		goto cleanup;
	skel_pkt1 = test_pkt_access__open_and_load();
	if (!ASSERT_OK_PTR(skel_pkt1, "skel_pkt1"))
		goto cleanup;
	prog_fd = bpf_program__fd(skel_pkt1->progs.test_pkt_access);
	bpf_program__set_attach_target(skel_trace1->progs.fentry1_bpf, prog_fd,
				       NULL);
	bpf_program__set_attach_target(skel_trace1->progs.fentry2_bpf, prog_fd,
				       NULL);
	bpf_program__set_attach_target(skel_trace1->progs.fexit1_bpf, prog_fd,
				       NULL);
	bpf_program__set_attach_target(skel_trace1->progs.fexit2_bpf, prog_fd,
				       NULL);
	bpf_program__set_attach_target(skel_trace1->progs.freplace1_bpf,
				       prog_fd, "test_pkt_access_subprog3");
	bpf_program__set_attach_target(skel_trace1->progs.freplace2_bpf,
				       prog_fd, "test_pkt_access_subprog3");
	bpf_program__set_attach_target(skel_trace1->progs.freplace3_bpf,
				       prog_fd, "get_skb_ifindex");
	err = prog_update_tracing__load(skel_trace1);
	if (!ASSERT_OK(err, "skel_trace1 load"))
		goto cleanup;
	trace_opts.cookie = expected_normal.fentry2_cookie;
	link = bpf_program__attach_trace_opts(skel_trace1->progs.fentry2,
					      &trace_opts);
	if (!ASSERT_OK_PTR(link, "attach fentry2"))
		goto cleanup;
	skel_trace1->links.fentry2 = link;
	trace_opts.cookie = expected_normal.fentry1_cookie;
	link = bpf_program__attach_trace_opts(skel_trace1->progs.fentry1,
					      &trace_opts);
	if (!ASSERT_OK_PTR(link, "attach fentry1"))
		goto cleanup;
	skel_trace1->links.fentry1 = link;
	trace_opts.cookie = expected_normal.fmod_ret2_cookie;
	link = bpf_program__attach_trace_opts(skel_trace1->progs.fmod_ret2,
					      &trace_opts);
	if (!ASSERT_OK_PTR(link, "attach fmod_ret2"))
		goto cleanup;
	skel_trace1->links.fmod_ret2 = link;
	trace_opts.cookie = expected_normal.fmod_ret1_cookie;
	link = bpf_program__attach_trace_opts(skel_trace1->progs.fmod_ret1,
					      &trace_opts);
	if (!ASSERT_OK_PTR(link, "attach fmod_ret1"))
		goto cleanup;
	skel_trace1->links.fmod_ret1 = link;
	trace_opts.cookie = expected_normal.fexit2_cookie;
	link = bpf_program__attach_trace_opts(skel_trace1->progs.fexit2,
					      &trace_opts);
	if (!ASSERT_OK_PTR(link, "attach fexit2"))
		goto cleanup;
	skel_trace1->links.fexit2 = link;
	trace_opts.cookie = expected_normal.fexit1_cookie;
	link = bpf_program__attach_trace_opts(skel_trace1->progs.fexit1,
					      &trace_opts);
	if (!ASSERT_OK_PTR(link, "attach fexit1"))
		goto cleanup;
	skel_trace1->links.fexit1 = link;
	trace_opts.cookie = expected_normal.fentry2_bpf_cookie;
	link = bpf_program__attach_trace_opts(skel_trace1->progs.fentry2_bpf,
					      &trace_opts);
	if (!ASSERT_OK_PTR(link, "attach fentry2_bpf"))
		goto cleanup;
	skel_trace1->links.fentry2_bpf = link;
	trace_opts.cookie = expected_normal.fentry1_bpf_cookie;
	link = bpf_program__attach_trace_opts(skel_trace1->progs.fentry1_bpf,
					      &trace_opts);
	if (!ASSERT_OK_PTR(link, "attach fentry1_bpf"))
		goto cleanup;
	skel_trace1->links.fentry1_bpf = link;
	trace_opts.cookie = expected_normal.fexit2_bpf_cookie;
	link = bpf_program__attach_trace_opts(skel_trace1->progs.fexit2_bpf,
					      &trace_opts);
	if (!ASSERT_OK_PTR(link, "attach fexit2_bpf"))
		goto cleanup;
	skel_trace1->links.fexit2_bpf = link;
	trace_opts.cookie = expected_normal.fexit1_bpf_cookie;
	link = bpf_program__attach_trace_opts(skel_trace1->progs.fexit1_bpf,
					      &trace_opts);
	if (!ASSERT_OK_PTR(link, "attach fexit1_bpf"))
		goto cleanup;
	skel_trace1->links.fexit1_bpf = link;
	link = bpf_program__attach_trace(skel_trace1->progs.freplace1_bpf);
	if (!ASSERT_OK_PTR(link, "attach freplace1_bpf"))
		goto cleanup;
	skel_trace1->links.freplace1_bpf = link;
	if (!assert_program_order(skel_trace1, skel_pkt1, &expected_normal))
		goto cleanup;

	/* Program update should fail if expected_attach_type is a mismatch. */
	err = bpf_link__update_program(skel_trace1->links.fentry1,
				       skel_trace1->progs.fexit1);
	if (!ASSERT_EQ(err, -EINVAL,
		       "fentry1 update wrong expected_attach_type"))
		goto cleanup;
	if (!assert_program_order(skel_trace1, skel_pkt1, &expected_normal))
		goto cleanup;

	/* Program update should fail if type is a mismatch. */
	err = bpf_link__update_program(skel_trace1->links.fentry1,
				       skel_pkt1->progs.test_pkt_access);
	if (!ASSERT_EQ(err, -EINVAL, "fentry1 update wrong type"))
		goto cleanup;
	if (!assert_program_order(skel_trace1, skel_pkt1, &expected_normal))
		goto cleanup;

	/* Program update should fail if program is incompatible */
	err = bpf_link__update_program(skel_trace1->links.freplace1_bpf,
				       skel_trace1->progs.freplace3_bpf);
	if (!ASSERT_EQ(err, -EINVAL, "freplace1_bpf update incompatible"))
		goto cleanup;
	if (!assert_program_order(skel_trace1, skel_pkt1, &expected_normal))
		goto cleanup;

	/* Update with BPF_F_REPLACE should fail if old_prog_fd does not match
	 * current link program.
	 */
	prog_fd = bpf_program__fd(skel_trace1->progs.fentry2);
	link_fd = bpf_link__fd(skel_trace1->links.fentry1);
	update_opts.old_prog_fd = bpf_program__fd(skel_trace1->progs.fentry2);
	update_opts.flags = BPF_F_REPLACE;
	err = bpf_link_update(link_fd, prog_fd, &update_opts);
	if (!ASSERT_EQ(err, -EPERM, "BPF_F_REPLACE EPERM"))
		goto cleanup;
	if (!assert_program_order(skel_trace1, skel_pkt1, &expected_normal))
		goto cleanup;

	/* Do an in-place swap of program order using link updates.
	 *
	 * Update with BPF_F_REPLACE should succeed if old_prog_fd matches
	 * current link program.
	 * Update should succeed if the new program's dst_trampoline has been
	 * cleared by a previous attach operation.
	 */
	update_opts.old_prog_fd = bpf_program__fd(skel_trace1->progs.fentry1);
	err = bpf_link_update(link_fd, prog_fd, &update_opts);
	if (!ASSERT_OK(err, "BPF_F_REPLACE"))
		goto cleanup;
	err = bpf_link__update_program(skel_trace1->links.fentry2,
				       skel_trace1->progs.fentry1);
	if (!ASSERT_OK(err, "fentry2 update"))
		goto cleanup;
	err = bpf_link__update_program(skel_trace1->links.fmod_ret1,
				       skel_trace1->progs.fmod_ret2);
	if (!ASSERT_OK(err, "fmod_ret1 update"))
		goto cleanup;
	err = bpf_link__update_program(skel_trace1->links.fmod_ret2,
				       skel_trace1->progs.fmod_ret1);
	if (!ASSERT_OK(err, "fmod_ret2 update"))
		goto cleanup;
	err = bpf_link__update_program(skel_trace1->links.fexit1,
				       skel_trace1->progs.fexit2);
	if (!ASSERT_OK(err, "fexit1 update"))
		goto cleanup;
	err = bpf_link__update_program(skel_trace1->links.fexit2,
				       skel_trace1->progs.fexit1);
	if (!ASSERT_OK(err, "fexit2 update"))
		goto cleanup;
	err = bpf_link__update_program(skel_trace1->links.fentry1_bpf,
				       skel_trace1->progs.fentry2_bpf);
	if (!ASSERT_OK(err, "fentry1_bpf update"))
		goto cleanup;
	err = bpf_link__update_program(skel_trace1->links.fentry2_bpf,
				       skel_trace1->progs.fentry1_bpf);
	if (!ASSERT_OK(err, "fentry2_bpf update"))
		goto cleanup;
	err = bpf_link__update_program(skel_trace1->links.fexit1_bpf,
				       skel_trace1->progs.fexit2_bpf);
	if (!ASSERT_OK(err, "fexit1_bpf update"))
		goto cleanup;
	err = bpf_link__update_program(skel_trace1->links.fexit2_bpf,
				       skel_trace1->progs.fexit1_bpf);
	if (!ASSERT_OK(err, "fexit2_bpf update"))
		goto cleanup;
	/* Only one freplace program can be attached at a time, so instead of
	 * swapping the order as with fentry/fmod_ret/fexit just shuffle
	 * freplace1_bpf and freplace_bpf2.
	 */
	err = bpf_link__destroy(skel_trace1->links.freplace1_bpf);
	if (!ASSERT_OK(err, "freplace1_bpf destroy"))
		goto cleanup;
	skel_trace1->links.freplace1_bpf = NULL;
	link = bpf_program__attach_trace(skel_trace1->progs.freplace2_bpf);
	if (!ASSERT_OK_PTR(link, "attach freplace2_bpf"))
		goto cleanup;
	skel_trace1->links.freplace2_bpf = link;
	err = bpf_link__update_program(skel_trace1->links.freplace2_bpf,
				       skel_trace1->progs.freplace1_bpf);
	if (!ASSERT_OK(err, "freplace2_bpf update"))
		goto cleanup;
	if (!assert_program_order(skel_trace1, skel_pkt1, &expected_inverted))
		goto cleanup;

	/* Update should work when the new program's dst_trampoline points to
	 * another trampoline or the same trampoline.
	 */
	skel_trace2 = prog_update_tracing__open();
	if (!ASSERT_OK_PTR(skel_trace2, "skel_trace2"))
		goto cleanup;
	skel_pkt2 = test_pkt_access__open_and_load();
	if (!ASSERT_OK_PTR(skel_pkt2, "skel_pkt2"))
		goto cleanup;
	prog_fd = bpf_program__fd(skel_pkt2->progs.test_pkt_access);
	bpf_program__set_attach_target(skel_trace2->progs.fentry1_bpf, prog_fd,
				       NULL);
	bpf_program__set_attach_target(skel_trace2->progs.fentry2_bpf, prog_fd,
				       NULL);
	bpf_program__set_attach_target(skel_trace2->progs.fexit1_bpf, prog_fd,
				       NULL);
	bpf_program__set_attach_target(skel_trace2->progs.fexit2_bpf, prog_fd,
				       NULL);
	bpf_program__set_attach_target(skel_trace2->progs.freplace1_bpf,
				       prog_fd, "test_pkt_access_subprog3");
	bpf_program__set_attach_target(skel_trace2->progs.freplace2_bpf,
				       prog_fd, "test_pkt_access_subprog3");
	bpf_program__set_attach_target(skel_trace2->progs.freplace3_bpf,
				       prog_fd, "get_skb_ifindex");
	err = prog_update_tracing__load(skel_trace2);
	if (!ASSERT_OK(err, "skel_trace2 load"))
		goto cleanup;
	err = bpf_link__update_program(skel_trace1->links.fentry1,
				       skel_trace2->progs.fentry1);
	if (!ASSERT_OK(err, "fentry1 update"))
		goto cleanup;
	err = bpf_link__update_program(skel_trace1->links.fentry2,
				       skel_trace2->progs.fentry2);
	if (!ASSERT_OK(err, "fentry2 update"))
		goto cleanup;
	err = bpf_link__update_program(skel_trace1->links.fmod_ret1,
				       skel_trace2->progs.fmod_ret1);
	if (!ASSERT_OK(err, "fmod_ret1 update"))
		goto cleanup;
	err = bpf_link__update_program(skel_trace1->links.fmod_ret2,
				       skel_trace2->progs.fmod_ret2);
	if (!ASSERT_OK(err, "fmod_ret2 update"))
		goto cleanup;
	err = bpf_link__update_program(skel_trace1->links.fexit1,
				       skel_trace2->progs.fexit1);
	if (!ASSERT_OK(err, "fexit1 update"))
		goto cleanup;
	err = bpf_link__update_program(skel_trace1->links.fexit2,
				       skel_trace2->progs.fexit2);
	if (!ASSERT_OK(err, "fexit2 update"))
		goto cleanup;
	err = bpf_link__update_program(skel_trace1->links.fentry1_bpf,
				       skel_trace2->progs.fentry1_bpf);
	if (!ASSERT_OK(err, "fentry1_bpf update"))
		goto cleanup;
	err = bpf_link__update_program(skel_trace1->links.fentry2_bpf,
				       skel_trace2->progs.fentry2_bpf);
	if (!ASSERT_OK(err, "fentry2_bpf update"))
		goto cleanup;
	err = bpf_link__update_program(skel_trace1->links.freplace2_bpf,
				       skel_trace2->progs.freplace1_bpf);
	if (!ASSERT_OK(err, "freplace2_bpf update"))
		goto cleanup;
	err = bpf_link__update_program(skel_trace1->links.fexit1_bpf,
				       skel_trace2->progs.fexit1_bpf);
	if (!ASSERT_OK(err, "fexit1_bpf update"))
		goto cleanup;
	err = bpf_link__update_program(skel_trace1->links.fexit2_bpf,
				       skel_trace2->progs.fexit2_bpf);
	if (!ASSERT_OK(err, "fexit2_bpf update"))
		goto cleanup;
	if (!assert_program_order(skel_trace2, skel_pkt1, &expected_normal))
		goto cleanup;

	/* Update should work when the new program is the same as the current
	 * program.
	 */
	err = bpf_link__update_program(skel_trace1->links.fentry1,
				       skel_trace2->progs.fentry1);
	if (!ASSERT_OK(err, "fentry1 update"))
		goto cleanup;
	if (!assert_program_order(skel_trace2, skel_pkt1, &expected_normal))
		goto cleanup;
cleanup:
	prog_update_tracing__destroy(skel_trace1);
	prog_update_tracing__destroy(skel_trace2);
	test_pkt_access__destroy(skel_pkt1);
	test_pkt_access__destroy(skel_pkt2);
}
