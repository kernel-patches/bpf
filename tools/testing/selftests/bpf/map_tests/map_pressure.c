// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Isovalent */

#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <bpf_util.h>
#include <test_maps.h>

#define MAX_ENTRIES 4096
#define N_THREADS 17

#define MAX_MAP_KEY_SIZE (sizeof(struct bpf_lpm_trie_key) + 4)

static void map_info(int map_fd, struct bpf_map_info *info)
{
	__u32 len = sizeof(*info);
	int ret;

	memset(info, 0, sizeof(*info));

	ret = bpf_obj_get_info_by_fd(map_fd, info, &len);
	CHECK(ret < 0, "bpf_obj_get_info_by_fd", "error: %s\n", strerror(errno));
}

static const char *map_type_to_s(__u32 type)
{
	switch (type) {
	case BPF_MAP_TYPE_HASH:
		return "HASH";
	case BPF_MAP_TYPE_PERCPU_HASH:
		return "PERCPU_HASH";
	case BPF_MAP_TYPE_LRU_HASH:
		return "LRU_HASH";
	case BPF_MAP_TYPE_LRU_PERCPU_HASH:
		return "LRU_PERCPU_HASH";
	case BPF_MAP_TYPE_LPM_TRIE:
		return "LPM_TRIE";
	default:
		return "<define-me>";
	}
}

/* Map index -> map-type-specific-key */
static void *map_key(__u32 type, __u32 i)
{
	static __thread __u8 key[MAX_MAP_KEY_SIZE];

	if (type == BPF_MAP_TYPE_LPM_TRIE) {
		/* prefixlen = 32, data[0..3] = i */
		*(__u32 *)key = 32;
		*(__u32 *)(key+4) = i;
	} else {
		*(__u32 *)key = i;
	}
	return key;
}

static __u32 map_count_elements(__u32 type, int map_fd)
{
	void *key = map_key(type, -1);
	int n = 0;

	while (!bpf_map_get_next_key(map_fd, key, key))
		n++;
	return n;
}

static void delete_all_elements(__u32 type, int map_fd)
{
	void *key = map_key(type, -1);
	void *keys;
	int n = 0;
	int ret;

	keys = calloc(MAX_MAP_KEY_SIZE, MAX_ENTRIES);
	CHECK(!keys, "calloc", "error: %s\n", strerror(errno));

	for (; !bpf_map_get_next_key(map_fd, key, key); n++)
		memcpy(keys + n*MAX_MAP_KEY_SIZE, key, MAX_MAP_KEY_SIZE);

	while (--n >= 0) {
		ret = bpf_map_delete_elem(map_fd, keys + n*MAX_MAP_KEY_SIZE);
		CHECK(ret < 0, "bpf_map_delete_elem", "error: %s\n", strerror(errno));
	}
}

static bool is_lru(__u32 map_type)
{
	return map_type == BPF_MAP_TYPE_LRU_HASH ||
	       map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH;
}

struct upsert_opts {
	__u32 map_type;
	int map_fd;
	__u32 n;
};

static void *patch_map_thread(void *arg)
{
	struct upsert_opts *opts = arg;
	void *key;
	int val;
	int ret;
	int i;

	for (i = 0; i < opts->n; i++) {
		key = map_key(opts->map_type, i);
		val = rand();
		ret = bpf_map_update_elem(opts->map_fd, key, &val, 0);
		CHECK(ret < 0, "bpf_map_update_elem", "error: %s\n", strerror(errno));
	}
	return NULL;
}

static void upsert_elements(struct upsert_opts *opts)
{
	pthread_t threads[N_THREADS];
	int ret;
	int i;

	for (i = 0; i < ARRAY_SIZE(threads); i++) {
		ret = pthread_create(&i[threads], NULL, patch_map_thread, opts);
		CHECK(ret != 0, "pthread_create", "error: %s\n", strerror(ret));
	}

	for (i = 0; i < ARRAY_SIZE(threads); i++) {
		ret = pthread_join(i[threads], NULL);
		CHECK(ret != 0, "pthread_join", "error: %s\n", strerror(ret));
	}
}

static void __test_map_pressure(int map_fd)
{
	__u32 n = MAX_ENTRIES - 1000, current_elements;
	struct upsert_opts opts = {
		.map_fd = map_fd,
		.n = n,
	};
	struct bpf_map_info info;

	map_info(map_fd, &info);
	opts.map_type = info.type;

	/*
	 * Upsert keys [0, n) under some competition: with random values from
	 * N_THREADS threads
	 */
	upsert_elements(&opts);

	/*
	 * Raw pressure for all hashtable-based maps should be equal to the
	 * number of elements present in the map. For non-lru maps this number
	 * should be the number n of upserted elements. For lru maps some
	 * elements might have been evicted. Check that all numbers make sense
	 */
	map_info(map_fd, &info);
	current_elements = map_count_elements(info.type, map_fd);
	if (!is_lru(info.type))
		CHECK(n != current_elements, "map_count_elements",
		      "current_elements(%u) != expected(%u)", current_elements, n);
	CHECK(info.raw_pressure != current_elements, "map_pressure",
	      "raw_pressure=%u, expected %u (map_type=%s,map_flags=%08x)\n",
	      info.raw_pressure, current_elements, map_type_to_s(info.type), info.map_flags);

	/*
	 * Cleanup the map and check that all elements are actually gone and
	 * that the map raw_pressure is back to 0 as well
	 */
	delete_all_elements(info.type, map_fd);
	map_info(map_fd, &info);
	current_elements = map_count_elements(info.type, map_fd);
	CHECK(current_elements, "map_count_elements",
	      "expected current_elements=0, got %u", current_elements);
	CHECK(info.raw_pressure != 0, "map_pressure",
	      "raw_pressure=%u, expected 0 (map_type=%s,map_flags=%08x)\n",
	      info.raw_pressure, map_type_to_s(info.type), info.map_flags);

	close(map_fd);
}

static int map_create_opts(__u32 type, const char *name,
			   struct bpf_map_create_opts *map_opts,
			   __u32 key_size, __u32 val_size)
{
	int map_fd;

	map_fd = bpf_map_create(type, name, key_size, val_size, MAX_ENTRIES, map_opts);
	CHECK(map_fd < 0, "bpf_map_create()", "error:%s (name=%s)\n",
			strerror(errno), name);

	return map_fd;
}

static int map_create(__u32 type, const char *name, struct bpf_map_create_opts *map_opts)
{
	return map_create_opts(type, name, map_opts, sizeof(int), sizeof(int));
}

static int create_hash(void)
{
	struct bpf_map_create_opts map_opts = {
		.sz = sizeof(map_opts),
		.map_flags = BPF_F_NO_PREALLOC,
	};

	return map_create(BPF_MAP_TYPE_HASH, "hash", &map_opts);
}

static int create_percpu_hash(void)
{
	struct bpf_map_create_opts map_opts = {
		.sz = sizeof(map_opts),
		.map_flags = BPF_F_NO_PREALLOC,
	};

	return map_create(BPF_MAP_TYPE_PERCPU_HASH, "percpu_hash", &map_opts);
}

static int create_hash_prealloc(void)
{
	return map_create(BPF_MAP_TYPE_HASH, "hash", NULL);
}

static int create_percpu_hash_prealloc(void)
{
	return map_create(BPF_MAP_TYPE_PERCPU_HASH, "percpu_hash_prealloc", NULL);
}

static int create_lru_hash(void)
{
	return map_create(BPF_MAP_TYPE_LRU_HASH, "lru_hash", NULL);
}

static int create_percpu_lru_hash(void)
{
	return map_create(BPF_MAP_TYPE_LRU_PERCPU_HASH, "lru_hash_percpu", NULL);
}

static int create_lpm_trie(void)
{
	struct bpf_map_create_opts map_opts = {
		.sz = sizeof(map_opts),
		.map_flags = BPF_F_NO_PREALLOC,
	};
	__u32 key_size = sizeof(struct bpf_lpm_trie_key) + 4;
	__u32 val_size = sizeof(int);

	return map_create_opts(BPF_MAP_TYPE_LPM_TRIE, "lpm_trie",
			       &map_opts, key_size, val_size);
}

static void map_pressure_hash(void)
{
	__test_map_pressure(create_hash());
	printf("test_%s:PASS\n", __func__);
}

static void map_pressure_percpu_hash(void)
{
	__test_map_pressure(create_percpu_hash());
	printf("test_%s:PASS\n", __func__);
}

static void map_pressure_hash_prealloc(void)
{
	__test_map_pressure(create_hash_prealloc());
	printf("test_%s:PASS\n", __func__);
}

static void map_pressure_percpu_hash_prealloc(void)
{
	__test_map_pressure(create_percpu_hash_prealloc());
	printf("test_%s:PASS\n", __func__);
}

static void map_pressure_lru_hash(void)
{
	__test_map_pressure(create_lru_hash());
	printf("test_%s:PASS\n", __func__);
}

static void map_pressure_percpu_lru_hash(void)
{
	__test_map_pressure(create_percpu_lru_hash());
	printf("test_%s:PASS\n", __func__);
}

static void map_pressure_lpm_trie(void)
{
	__test_map_pressure(create_lpm_trie());
	printf("test_%s:PASS\n", __func__);
}

void test_map_pressure(void)
{
	map_pressure_hash();
	map_pressure_percpu_hash();
	map_pressure_hash_prealloc();
	map_pressure_percpu_hash_prealloc();
	map_pressure_lru_hash();
	map_pressure_percpu_lru_hash();
	map_pressure_lpm_trie();
}
