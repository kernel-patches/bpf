// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#include <test_progs.h>
#include <sys/syscall.h>
#include "linked_maps.skel.h"

void test_linked_maps(void)
{
	int key1 = 1, key2 = 2;
	int val1 = 42, val2 = 24, val;
	int err, map_fd1, map_fd2;
	struct linked_maps *skel;

	skel = linked_maps__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	map_fd1 = bpf_map__fd(skel->maps.linked_maps1__map_static);
	ASSERT_OK(bpf_map_update_elem(map_fd1, &key2, &val2, 0), "static_map1_update");

	map_fd2 = bpf_map__fd(skel->maps.linked_maps2__map_static);
	ASSERT_OK(bpf_map_update_elem(map_fd2, &key1, &val1, 0), "static_map2_update");

	err = linked_maps__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto cleanup;

	/* trigger */
	syscall(SYS_getpgid);

	ASSERT_EQ(skel->bss->output_first1, 2000, "output_first1");
	ASSERT_EQ(skel->bss->output_second1, 2, "output_second1");
	ASSERT_EQ(skel->bss->output_weak1, 2, "output_weak1");
	ASSERT_EQ(skel->bss->output_static1, val2, "output_static1");
	ASSERT_OK(bpf_map_lookup_elem(map_fd1, &key1, &val), "static_map1_lookup");
	ASSERT_EQ(val, 1, "static_map1_key1");

	ASSERT_EQ(skel->bss->output_first2, 1000, "output_first2");
	ASSERT_EQ(skel->bss->output_second2, 1, "output_second2");
	ASSERT_EQ(skel->bss->output_weak2, 1, "output_weak2");
	ASSERT_EQ(skel->bss->output_static2, val1, "output_static2");
	ASSERT_OK(bpf_map_lookup_elem(map_fd2, &key2, &val), "static_map2_lookup");
	ASSERT_EQ(val, 2, "static_map2_key2");

cleanup:
	linked_maps__destroy(skel);
}
