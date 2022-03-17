// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>

#include "map_kptr.skel.h"

void test_map_kptr(void)
{
	struct map_kptr *skel;
	char buf[24];
	int key = 0;

	skel = map_kptr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "map_kptr__open_and_load"))
		return;
	ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.hash_map), &key, buf, 0),
		  "bpf_map_update_elem hash_map");
	ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.hash_malloc_map), &key, buf, 0),
		  "bpf_map_update_elem hash_malloc_map");
	map_kptr__destroy(skel);
}
