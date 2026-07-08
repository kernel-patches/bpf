// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 David Windsor */

/*
 * Regression test for the x86 BPF dispatcher's indirect-jump fallback
 * under FineIBT.
 *
 * WARNING
 * -------
 *  This test can crash the kernel, thus should be run in a VM.
 */
#include <uapi/linux/if_link.h>
#include <test_progs.h>
#include <network_helpers.h>
#include "xdp_dispatcher_fineibt.skel.h"

#define IFINDEX_LO		1

void test_xdp_dispatcher_fineibt(void)
{
	struct xdp_dispatcher_fineibt *skel;
	int err, attached_fd, unattached_fd;

	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
	);

	skel = xdp_dispatcher_fineibt__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	attached_fd = bpf_program__fd(skel->progs.xdp_dispatcher_attached);
	unattached_fd = bpf_program__fd(skel->progs.xdp_dispatcher_unattached);

	err = bpf_xdp_attach(IFINDEX_LO, attached_fd, XDP_FLAGS_SKB_MODE, NULL);
	if (!ASSERT_OK(err, "attach_prog"))
		goto out;

	err = bpf_prog_test_run_opts(unattached_fd, &topts);
	ASSERT_OK(err, "unattached_test_run");
	ASSERT_EQ(topts.retval, XDP_PASS, "unattached_retval");

	bpf_xdp_detach(IFINDEX_LO, XDP_FLAGS_SKB_MODE, NULL);
out:
	xdp_dispatcher_fineibt__destroy(skel);
}
