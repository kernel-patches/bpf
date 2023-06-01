// SPDX-License-Identifier: GPL-2.0-only

#include <test_progs.h>

#include "test_map_in_map_inner_array_lookup.skel.h"

static int duration;

void test_map_in_map_inner_array_lookup(void)
{
	int map1_fd, err;
	int key = 3;
	int val = 1;
	struct test_map_in_map_inner_array_lookup *skel;

	skel = test_map_in_map_inner_array_lookup__open_and_load();
	if (CHECK(!skel, "skel_open", "failed to open&load skeleton\n"))
		return;

	err = test_map_in_map_inner_array_lookup__attach(skel);
	if (CHECK(err, "skel_attach", "skeleton attach failed: %d\n", err))
		goto cleanup;

	map1_fd = bpf_map__fd(skel->maps.inner_map1);
	bpf_map_update_elem(map1_fd, &key, &val, 0);
	usleep(1);
	/* Probe should have set the element at index 3 to 2 */
	bpf_map_lookup_elem(map1_fd, &key, &val);
	CHECK(val != 2, "inner1", "got %d != exp %d\n", val, 2);

cleanup:
	test_map_in_map_inner_array_lookup__destroy(skel);
}
