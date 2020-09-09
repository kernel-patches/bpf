// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright 2020 Google LLC.
 */

#include <test_progs.h>
#include <cgroup_helpers.h>
#include <network_helpers.h>

#include "metadata_unused.skel.h"
#include "metadata_used.skel.h"

static int duration;

static void test_metadata_unused(void)
{
	struct metadata_unused *obj;
	int err;

	obj = metadata_unused__open_and_load();
	if (CHECK(!obj, "skel-load", "errno %d", errno))
		return;

	/* Assert that we can access the metadata in skel and the values are
	 * what we expect.
	 */
	if (CHECK(strncmp(obj->rodata->bpf_metadata_a, "foo",
			  sizeof(obj->rodata->bpf_metadata_a)),
		  "bpf_metadata_a", "expected \"foo\", value differ"))
		goto close_bpf_object;
	if (CHECK(obj->rodata->bpf_metadata_b != 1, "bpf_metadata_b",
		  "expected 1, got %d", obj->rodata->bpf_metadata_b))
		goto close_bpf_object;

	/* Assert that binding metadata map to prog again succeeds. */
	err = bpf_prog_bind_map(bpf_program__fd(obj->progs.prog),
				bpf_map__fd(obj->maps.rodata), NULL);
	CHECK(err, "rebind_map", "errno %d, expected 0", errno);

close_bpf_object:
	metadata_unused__destroy(obj);
}

static void test_metadata_used(void)
{
	struct metadata_used *obj;
	int err;

	obj = metadata_used__open_and_load();
	if (CHECK(!obj, "skel-load", "errno %d", errno))
		return;

	/* Assert that we can access the metadata in skel and the values are
	 * what we expect.
	 */
	if (CHECK(strncmp(obj->rodata->bpf_metadata_a, "bar",
			  sizeof(obj->rodata->bpf_metadata_a)),
		  "metadata_a", "expected \"bar\", value differ"))
		goto close_bpf_object;
	if (CHECK(obj->rodata->bpf_metadata_b != 2, "metadata_b",
		  "expected 2, got %d", obj->rodata->bpf_metadata_b))
		goto close_bpf_object;

	/* Assert that binding metadata map to prog again succeeds. */
	err = bpf_prog_bind_map(bpf_program__fd(obj->progs.prog),
				bpf_map__fd(obj->maps.rodata), NULL);
	CHECK(err, "rebind_map", "errno %d, expected 0", errno);

close_bpf_object:
	metadata_used__destroy(obj);
}

void test_metadata(void)
{
	if (test__start_subtest("unused"))
		test_metadata_unused();

	if (test__start_subtest("used"))
		test_metadata_used();
}
