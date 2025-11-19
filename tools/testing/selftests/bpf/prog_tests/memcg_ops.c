// SPDX-License-Identifier: GPL-2.0
/*
 * Memory controller eBPF struct ops test
 */

#include <test_progs.h>
#include <bpf/btf.h>

void test_memcg_ops_load(void)
{
	struct bpf_object *obj;
	int err;

	obj = bpf_object__open_file("memcg_ops.bpf.o", NULL);
	err = libbpf_get_error(obj);
	if (CHECK_FAIL(err)) {
		obj = NULL;
		goto out;
	}

	err = bpf_object__load(obj);
	if (CHECK_FAIL(err))
		goto out;

out:
	if (obj)
		bpf_object__close(obj);
}

void test_memcg_ops_attach(void)
{
	struct bpf_object *obj;
	struct bpf_map *map;
	struct bpf_link *link = NULL;
	int err;

	obj = bpf_object__open_file("memcg_ops.bpf.o", NULL);
	err = libbpf_get_error(obj);
	if (CHECK_FAIL(err)) {
		obj = NULL;
		goto out;
	}

	err = bpf_object__load(obj);
	if (CHECK_FAIL(err))
		goto out;

	map = bpf_object__find_map_by_name(obj, "mcg_ops");
	if (!ASSERT_OK_PTR(map, "bpf_object__find_map_by_name"))
		goto out;

	link = bpf_map__attach_struct_ops(map);
	if (!ASSERT_OK_PTR(link, "bpf_map__attach_struct_ops"))
		goto out;

out:
	if (link)
		bpf_link__destroy(link);
	if (obj)
		bpf_object__close(obj);
}

void test_memcg_ops_double_attach(void)
{
	struct bpf_object *obj, *obj2;
	struct bpf_map *map, *map2;
	struct bpf_link *link = NULL, *link2 = NULL;
	int err;

	obj = bpf_object__open_file("memcg_ops.bpf.o", NULL);
	err = libbpf_get_error(obj);
	if (CHECK_FAIL(err)) {
		obj = NULL;
		goto out;
	}

	err = bpf_object__load(obj);
	if (CHECK_FAIL(err))
		goto out;

	map = bpf_object__find_map_by_name(obj, "mcg_ops");
	if (!ASSERT_OK_PTR(map, "bpf_object__find_map_by_name"))
		goto out;

	link = bpf_map__attach_struct_ops(map);
	if (!ASSERT_OK_PTR(link, "bpf_map__attach_struct_ops"))
		goto out;

	obj2 = bpf_object__open_file("memcg_ops.bpf.o", NULL);
	err = libbpf_get_error(obj2);
	if (CHECK_FAIL(err)) {
		obj2 = NULL;
		goto out;
	}

	err = bpf_object__load(obj2);
	if (CHECK_FAIL(err))
		goto out;

	map2 = bpf_object__find_map_by_name(obj2, "mcg_ops");
	if (!ASSERT_OK_PTR(map, "bpf_object__find_map_by_name"))
		goto out;

	link2 = bpf_map__attach_struct_ops(map2);
	if (!ASSERT_ERR_PTR(link2, "bpf_map__attach_struct_ops")) {
		bpf_link__destroy(link2);
		goto out;
	}

out:
	if (link)
		bpf_link__destroy(link);
	if (obj)
		bpf_object__close(obj);
	if (obj2)
		bpf_object__close(obj2);
}
