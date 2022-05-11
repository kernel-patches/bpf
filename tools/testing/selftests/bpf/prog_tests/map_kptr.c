// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>

#include "map_kptr.skel.h"

void test_map_kptr(void)
{
	struct map_kptr *skel;
	int key = 0, ret;
	char buf[16];

	skel = map_kptr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "map_kptr__open_and_load"))
		return;

	ret = bpf_map__update_elem(skel->maps.array_map,
				   &key, sizeof(key), buf, sizeof(buf), 0);
	ASSERT_OK(ret, "array_map update");
	ret = bpf_map__update_elem(skel->maps.array_map,
				   &key, sizeof(key), buf, sizeof(buf), 0);
	ASSERT_OK(ret, "array_map update2");

	ret = bpf_map__update_elem(skel->maps.hash_map,
				   &key, sizeof(key), buf, sizeof(buf), 0);
	ASSERT_OK(ret, "hash_map update");
	ret = bpf_map__delete_elem(skel->maps.hash_map, &key, sizeof(key), 0);
	ASSERT_OK(ret, "hash_map delete");

	ret = bpf_map__update_elem(skel->maps.hash_malloc_map,
				   &key, sizeof(key), buf, sizeof(buf), 0);
	ASSERT_OK(ret, "hash_malloc_map update");
	ret = bpf_map__delete_elem(skel->maps.hash_malloc_map, &key, sizeof(key), 0);
	ASSERT_OK(ret, "hash_malloc_map delete");

	ret = bpf_map__update_elem(skel->maps.lru_hash_map,
				   &key, sizeof(key), buf, sizeof(buf), 0);
	ASSERT_OK(ret, "lru_hash_map update");
	ret = bpf_map__delete_elem(skel->maps.lru_hash_map, &key, sizeof(key), 0);
	ASSERT_OK(ret, "lru_hash_map delete");

	map_kptr__destroy(skel);
}
