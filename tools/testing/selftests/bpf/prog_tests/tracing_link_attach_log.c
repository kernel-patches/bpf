// SPDX-License-Identifier: GPL-2.0
/* Copyright Leon Hwang */

#include <test_progs.h>
#include "tailcall_bpf2bpf1.skel.h"
#include "freplace_global_func.skel.h"

void test_freplace_attach_log(void)
{
	struct freplace_global_func *freplace_skel = NULL;
	struct tailcall_bpf2bpf1 *tailcall_skel = NULL;
	struct bpf_link *freplace_link = NULL;
	struct bpf_program *prog;
	int err, prog_fd;
	LIBBPF_OPTS(bpf_link_create_opts, link_opts);

	tailcall_skel = tailcall_bpf2bpf1__open_and_load();
	if (!ASSERT_OK_PTR(tailcall_skel, "tailcall_bpf2bpf1__open_and_load"))
		return;

	freplace_skel = freplace_global_func__open();
	if (!ASSERT_OK_PTR(freplace_skel, "freplace_global_func__open"))
		goto out;

	prog = freplace_skel->progs.new_test_pkt_access;
	prog_fd = bpf_program__fd(tailcall_skel->progs.entry);
	err = bpf_program__set_attach_target(prog, prog_fd, "entry");
	if (!ASSERT_OK(err, "bpf_program__set_attach_target"))
		goto out;

	err = freplace_global_func__load(freplace_skel);
	if (!ASSERT_OK(err, "freplace_global_func__load"))
		goto out;

	freplace_link = bpf_program__attach_freplace(prog, prog_fd, "subprog_tail");
	ASSERT_ERR_PTR(freplace_link, "bpf_program__attach_freplace");

out:
	bpf_link__destroy(freplace_link);
	freplace_global_func__destroy(freplace_skel);
	tailcall_bpf2bpf1__destroy(tailcall_skel);
}
