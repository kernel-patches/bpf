// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Facebook

#include <test_progs.h>
#include <network_helpers.h>

#include "map_ptr_kern.lskel.h"

void test_map_ptr(void)
{
	struct map_ptr_kern_lskel *skel;
	char buf[128];
	int err;
	int page_size = getpagesize();
	int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	/*
	 * Need to calc size of 'struct htab_elem' since it depends on
	 * host word size, but it's neither in a header nor can we include
	 * vmlinux.h here because that fails to compile.  Instead, use a
	 * simplified version of the struct for 32/64-bit sizing info.
	 */
	struct dummy_htab_elem {
		struct {
			void* a[4];
			int b;
		};
		int c;
		char d[] __attribute__((__aligned__(8)));
	};
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.data_out = buf,
		.data_size_out = sizeof(buf),
		.repeat = 1,
	);

	skel = map_ptr_kern_lskel__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	skel->maps.m_ringbuf.max_entries = page_size;
	skel->maps.m_cpumap.max_entries = num_cpus;

	err = map_ptr_kern_lskel__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	skel->bss->page_size = page_size;
	skel->bss->num_cpus = num_cpus;
	/*
	 * Determine size of struct htab_elem + key + val, noting the
	 * kernel rounds up our u32 key and val sizes by 8.
	 */
	skel->bss->htab_elem_size = sizeof(struct dummy_htab_elem) + 8 + 8;

	err = bpf_prog_test_run_opts(skel->progs.cg_skb.prog_fd, &topts);

	if (!ASSERT_OK(err, "test_run"))
		goto cleanup;

	if (!ASSERT_NEQ(topts.retval, 0, "test_run retval"))
		goto cleanup;

cleanup:
	map_ptr_kern_lskel__destroy(skel);
}
