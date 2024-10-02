// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Google */

#include <test_progs.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include "kmem_cache_iter.skel.h"

static void test_kmem_cache_iter_check_task(struct kmem_cache_iter *skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.flags = 0,  /* run it with the current task */
	);
	int prog_fd = bpf_program__fd(skel->progs.check_task_struct);

	/* get task_struct and check it if's from a slab cache */
	bpf_prog_test_run_opts(prog_fd, &opts);

	/* the BPF program should set 'found' variable */
	ASSERT_EQ(skel->bss->found, 1, "found task_struct");
}

void test_kmem_cache_iter(void)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	struct kmem_cache_iter *skel = NULL;
	union bpf_iter_link_info linfo = {};
	struct bpf_link *link;
	char buf[1024];
	int iter_fd;

	skel = kmem_cache_iter__open_and_load();
	if (!ASSERT_OK_PTR(skel, "kmem_cache_iter__open_and_load"))
		return;

	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	link = bpf_program__attach_iter(skel->progs.slab_info_collector, &opts);
	if (!ASSERT_OK_PTR(link, "attach_iter"))
		goto destroy;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (!ASSERT_GE(iter_fd, 0, "iter_create"))
		goto free_link;

	memset(buf, 0, sizeof(buf));
	while (read(iter_fd, buf, sizeof(buf) > 0)) {
		/* read out all contents */
		printf("%s", buf);
	}

	/* next reads should return 0 */
	ASSERT_EQ(read(iter_fd, buf, sizeof(buf)), 0, "read");

	test_kmem_cache_iter_check_task(skel);

	close(iter_fd);

free_link:
	bpf_link__destroy(link);
destroy:
	kmem_cache_iter__destroy(skel);
}
