// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google */
#include <test_progs.h>

#include <assert.h>
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "bpf_map_trace_delete_elem.skel.h"
#include "bpf_map_trace_loop0.skel.h"
#include "bpf_map_trace_loop1.skel.h"
#include "bpf_map_trace_update_elem.skel.h"

uint32_t collatz(uint32_t x)
{
	return x % 2 ? x * 3 + 1 : x / 2;
}

void update_elem__basic(void)
{
	const uint32_t tracer_value = collatz(0xdeadbeef);
	struct bpf_map_trace_update_elem *skel;
	const uint32_t tracer_key = 0x5;
	uint32_t value;
	int rc;

	skel = bpf_map_trace_update_elem__open_and_load();
	if (!ASSERT_NEQ(skel, NULL, "open/load skeleton failure"))
		return;
	rc = bpf_map_trace_update_elem__attach(skel);
	if (!ASSERT_EQ(rc, 0, "attach skeleton failure")) {
		fprintf(stderr, "Failed to attach skeleton: %d\n", errno);
		goto out;
	}

	/* The kprobe will place (0x5, 0xdeadbeef) in its map. The tracer will
	 * place (0x5, collatz(0xdeadbeef)) in its map. This map lookup will
	 * trigger the kprobe.
	 */
	rc = bpf_map_lookup_elem(bpf_map__fd(skel->maps.tracer_map),
				 &tracer_key, &value);
	if (!ASSERT_EQ(rc, 0, "map lookup failure")) {
		fprintf(stderr, "Failed to lookup tracer map: %s\n",
			strerror(errno));
		goto out;
	}
	if (!ASSERT_EQ(value, tracer_value, "map lookup mismatch"))
		goto out;

out:
	bpf_map_trace_update_elem__destroy(skel);
}

void delete_elem__basic(void)
{
	const uint32_t tracer_key = collatz(0x5);
	struct bpf_map_trace_delete_elem *skel;
	uint32_t value = 0;
	int rc;

	skel = bpf_map_trace_delete_elem__open_and_load();
	if (!ASSERT_NEQ(skel, NULL, "open/load skeleton failure"))
		return;
	rc = bpf_map_trace_delete_elem__attach(skel);
	if (!ASSERT_EQ(rc, 0, "attach skeleton failure")) {
		fprintf(stderr, "Failed to attach skeleton: %d\n", errno);
		goto out;
	}

	/* The kprobe will delete (0x5) from its map. The tracer will
	 * place (collatz(0x5), pid) in its map. This map lookup will trigger
	 * the kprobe.
	 */
	rc = bpf_map_lookup_elem(bpf_map__fd(skel->maps.tracer_map),
				 &tracer_key, &value);
	if (!ASSERT_EQ(rc, 0, "map lookup failure")) {
		fprintf(stderr, "Failed to lookup tracer map: %s\n",
			strerror(errno));
		goto out;
	}
	if (!ASSERT_EQ(value, getpid(), "map lookup mismatch"))
		goto out;

out:
	bpf_map_trace_delete_elem__destroy(skel);
}

void infinite_loop__direct(void)
{
	struct bpf_map_trace_loop0 *skel;
	struct bpf_link *tracer_link;

	skel = bpf_map_trace_loop0__open_and_load();
	if (!ASSERT_NEQ(skel, NULL, "open/load skeleton failure"))
		goto out;
	tracer_link = bpf_program__attach(skel->progs.tracer);
	if (!ASSERT_ERR_PTR(tracer_link, "link creation success"))
		goto out;

out:
	bpf_map_trace_loop0__destroy(skel);
}

void infinite_loop__indirect(void)
{
	struct bpf_map_trace_loop1 *skel;
	struct bpf_link *tracer_link;

	skel = bpf_map_trace_loop1__open_and_load();
	if (!ASSERT_NEQ(skel, NULL, "open/load skeleton failure"))
		return;
	tracer_link = bpf_program__attach(skel->progs.tracer0);
	if (!ASSERT_OK_PTR(tracer_link, "link creation failure"))
		goto out;
	tracer_link = bpf_program__attach(skel->progs.tracer1);
	if (!ASSERT_ERR_PTR(tracer_link, "link creation success"))
		goto out;

out:
	bpf_map_trace_loop1__destroy(skel);
}

void test_bpf_map_trace(void)
{
	if (test__start_subtest("update_elem__basic"))
		update_elem__basic();
	if (test__start_subtest("delete_elem__basic"))
		delete_elem__basic();
	if (test__start_subtest("infinite_loop__direct"))
		infinite_loop__direct();
	if (test__start_subtest("infinite_loop__indirect"))
		infinite_loop__indirect();
}

