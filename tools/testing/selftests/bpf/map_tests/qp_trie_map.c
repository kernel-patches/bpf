// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2022. Huawei Technologies Co., Ltd */
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <endian.h>
#include <limits.h>
#include <time.h>
#include <pthread.h>
#include <linux/btf.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <test_btf.h>
#include <test_maps.h>

#include "bpf_util.h"

#define QP_TRIE_KEY_SIZE sizeof(struct bpf_dynptr)
#define QP_TRIE_DFT_MAX_KEY_LEN 4
#define QP_TRIE_DFT_VAL_SIZE 4
#define QP_TRIE_DFT_MAP_FLAGS (BPF_F_NO_PREALLOC | BPF_F_DYNPTR_KEY)

#define QP_TRIE_DFT_BTF_KEY_ID 1
#define QP_TRIE_DFT_BTF_VAL_ID 2

struct qp_trie_create_case {
	const char *name;
	int error;
	unsigned int map_flags;
	unsigned int max_key_len;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int btf_key_type_id;
	unsigned int btf_value_type_id;
};

struct qp_trie_bytes_key {
	unsigned int len;
	unsigned char data[4];
};

struct qp_trie_int_key {
	unsigned int len;
	unsigned int data;
};

enum {
	UPDATE_OP = 0,
	DELETE_OP,
	LOOKUP_OP,
	ITERATE_OP,
	MAX_OP,
};

struct stress_conf {
	unsigned int threads[MAX_OP];
	unsigned int max_key_len;
	unsigned int loop;
	unsigned int nr;
};

struct qp_trie_rw_ctx {
	unsigned int nr;
	unsigned int max_key_len;
	int fd;
	struct bpf_dynptr_user *set;
	unsigned int loop;
	unsigned int nr_delete;
};

static int qp_trie_load_btf(void)
{
	const char btf_str_sec[] = "\0bpf_dynptr\0qp_test_key";
	__u32 btf_raw_types[] = {
		/* struct bpf_dynptr */				/* [1] */
		BTF_TYPE_ENC(1, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 0), 16),
		/* unsigned int */				/* [2] */
		BTF_TYPE_INT_ENC(0, 0, 0, 32, 4),
		/* struct qp_test_key */			/* [3] */
		BTF_TYPE_ENC(12, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 0), 16),
	};
	struct btf_header btf_hdr = {
		.magic = BTF_MAGIC,
		.version = BTF_VERSION,
		.hdr_len = sizeof(struct btf_header),
		.type_len = sizeof(btf_raw_types),
		.str_off = sizeof(btf_raw_types),
		.str_len = sizeof(btf_str_sec),
	};
	__u8 raw_btf[sizeof(struct btf_header) + sizeof(btf_raw_types) +
		     sizeof(btf_str_sec)];

	memcpy(raw_btf, &btf_hdr, sizeof(btf_hdr));
	memcpy(raw_btf + sizeof(btf_hdr), btf_raw_types, sizeof(btf_raw_types));
	memcpy(raw_btf + sizeof(btf_hdr) + sizeof(btf_raw_types),
	       btf_str_sec, sizeof(btf_str_sec));

	return bpf_btf_load(raw_btf, sizeof(raw_btf), NULL);
}

struct qp_trie_create_case create_cases[] = {
	{
		.name = "tiny qp-trie",
		.error = 0,
		.map_flags = QP_TRIE_DFT_MAP_FLAGS,
		.max_key_len = QP_TRIE_DFT_MAX_KEY_LEN,
		.value_size = QP_TRIE_DFT_VAL_SIZE,
		.max_entries = 1,
		.btf_key_type_id = QP_TRIE_DFT_BTF_KEY_ID,
		.btf_value_type_id = QP_TRIE_DFT_BTF_VAL_ID,
	},
	{
		.name = "empty qp-trie",
		.error = -EINVAL,
		.map_flags = QP_TRIE_DFT_MAP_FLAGS,
		.max_key_len = QP_TRIE_DFT_MAX_KEY_LEN,
		.value_size = QP_TRIE_DFT_VAL_SIZE,
		.max_entries = 0,
		.btf_key_type_id = QP_TRIE_DFT_BTF_KEY_ID,
		.btf_value_type_id = QP_TRIE_DFT_BTF_VAL_ID,
	},
	{
		.name = "preallocated qp-trie",
		.error = -EINVAL,
		.map_flags = BPF_F_DYNPTR_KEY,
		.max_key_len = QP_TRIE_DFT_MAX_KEY_LEN,
		.value_size = QP_TRIE_DFT_VAL_SIZE,
		.max_entries = 1,
		.btf_key_type_id = QP_TRIE_DFT_BTF_KEY_ID,
		.btf_value_type_id = QP_TRIE_DFT_BTF_VAL_ID,
	},
	{
		.name = "fixed-size key qp-trie",
		.error = -EINVAL,
		.map_flags = BPF_F_NO_PREALLOC,
		.max_key_len = QP_TRIE_DFT_MAX_KEY_LEN,
		.value_size = QP_TRIE_DFT_VAL_SIZE,
		.max_entries = 1,
		.btf_key_type_id = QP_TRIE_DFT_BTF_KEY_ID,
		.btf_value_type_id = QP_TRIE_DFT_BTF_VAL_ID,
	},
	{
		.name = "mmapable qp-trie",
		.error = -EINVAL,
		.map_flags = QP_TRIE_DFT_MAP_FLAGS | BPF_F_MMAPABLE,
		.max_key_len = QP_TRIE_DFT_MAX_KEY_LEN,
		.value_size = QP_TRIE_DFT_VAL_SIZE,
		.max_entries = 1,
		.btf_key_type_id = QP_TRIE_DFT_BTF_KEY_ID,
		.btf_value_type_id = QP_TRIE_DFT_BTF_VAL_ID,
	},
	{
		.name = "no btf qp-trie",
		.error = -EINVAL,
		.map_flags = QP_TRIE_DFT_MAP_FLAGS,
		.max_key_len = QP_TRIE_DFT_MAX_KEY_LEN,
		.value_size = QP_TRIE_DFT_VAL_SIZE,
		.max_entries = 1,
		.btf_key_type_id = 0,
		.btf_value_type_id = 0,
	},
	{
		.name = "qp_test_key qp-trie",
		.error = -EINVAL,
		.map_flags = QP_TRIE_DFT_MAP_FLAGS,
		.max_key_len = QP_TRIE_DFT_MAX_KEY_LEN,
		.value_size = QP_TRIE_DFT_VAL_SIZE,
		.max_entries = 1,
		.btf_key_type_id = 3,
		.btf_value_type_id = QP_TRIE_DFT_BTF_VAL_ID,
	},
	{
		.name = "zero max key len qp-trie",
		.error = -EINVAL,
		.map_flags = QP_TRIE_DFT_MAP_FLAGS,
		.max_key_len = 0,
		.value_size = QP_TRIE_DFT_VAL_SIZE,
		.max_entries = 1,
		.btf_key_type_id = QP_TRIE_DFT_BTF_KEY_ID,
		.btf_value_type_id = QP_TRIE_DFT_BTF_VAL_ID,
	},
	{
		.name = "big k-v size qp-trie",
		.error = -E2BIG,
		.map_flags = QP_TRIE_DFT_MAP_FLAGS,
		.max_key_len = QP_TRIE_DFT_MAX_KEY_LEN,
		.value_size = 128 << 20,
		.max_entries = 1,
		.btf_key_type_id = QP_TRIE_DFT_BTF_KEY_ID,
		.btf_value_type_id = QP_TRIE_DFT_BTF_VAL_ID,
	},
};

static void test_qp_trie_create(void)
{
	unsigned int i;
	int btf_fd;

	btf_fd = qp_trie_load_btf();
	CHECK(btf_fd < 0, "load btf", "error %d\n", btf_fd);

	for (i = 0; i < ARRAY_SIZE(create_cases); i++) {
		LIBBPF_OPTS(bpf_map_create_opts, opts);
		int fd;

		opts.map_flags = create_cases[i].map_flags;
		opts.btf_fd = btf_fd;
		opts.btf_key_type_id = create_cases[i].btf_key_type_id;
		opts.btf_value_type_id = create_cases[i].btf_value_type_id;
		opts.map_extra = create_cases[i].max_key_len;
		fd = bpf_map_create(BPF_MAP_TYPE_QP_TRIE, "qp_trie", QP_TRIE_KEY_SIZE,
				    create_cases[i].value_size, create_cases[i].max_entries, &opts);
		if (!create_cases[i].error) {
			CHECK(fd < 0, create_cases[i].name, "error %d\n", fd);
			close(fd);
		} else {
			CHECK(fd != create_cases[i].error, create_cases[i].name,
			      "expect error %d got %d\n", create_cases[i].error, fd);
		}
	}

	close(btf_fd);
}

static int qp_trie_create(unsigned int max_key_len, unsigned int value_size, unsigned int max_entries)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	int btf_fd, map_fd;

	btf_fd = qp_trie_load_btf();
	CHECK(btf_fd < 0, "load btf", "error %d\n", btf_fd);

	opts.map_flags = QP_TRIE_DFT_MAP_FLAGS;
	opts.btf_fd = btf_fd;
	opts.btf_key_type_id = QP_TRIE_DFT_BTF_KEY_ID;
	opts.btf_value_type_id = QP_TRIE_DFT_BTF_VAL_ID;
	opts.map_extra = max_key_len;
	map_fd = bpf_map_create(BPF_MAP_TYPE_QP_TRIE, "qp_trie", QP_TRIE_KEY_SIZE, value_size,
				max_entries, &opts);
	CHECK(map_fd < 0, "bpf_map_create", "error %d\n", map_fd);

	close(btf_fd);

	return map_fd;
}

static void test_qp_trie_bad_update(void)
{
	struct bpf_dynptr_user dynptr;
	unsigned int key, value;
	u64 big_key;
	int fd, err;

	fd = qp_trie_create(sizeof(key), sizeof(value), 1);

	/* Invalid flags (Error) */
	key = 0;
	value = 0;
	bpf_dynptr_user_init(&key, sizeof(key), &dynptr);
	err = bpf_map_update_elem(fd, &dynptr, &value, BPF_NOEXIST | BPF_EXIST);
	CHECK(err != -EINVAL, "invalid update flag", "error %d\n", err);

	/* Invalid key len (Error) */
	big_key = 1;
	value = 1;
	bpf_dynptr_user_init(&big_key, sizeof(big_key), &dynptr);
	err = bpf_map_update_elem(fd, &dynptr, &value, 0);
	CHECK(err != -EINVAL, "invalid data len", "error %d\n", err);

	/* Iterate an empty qp-trie (Error) */
	bpf_dynptr_user_init(&key, sizeof(key), &dynptr);
	err = bpf_map_get_next_key(fd, NULL, &dynptr);
	CHECK(err != -ENOENT, "non-empty qp-trie", "error %d\n", err);

	/* Overwrite an empty qp-trie (Error) */
	key = 2;
	value = 2;
	bpf_dynptr_user_init(&key, sizeof(key), &dynptr);
	err = bpf_map_update_elem(fd, &dynptr, &value, BPF_EXIST);
	CHECK(err != -ENOENT, "overwrite empty qp-trie", "error %d\n", err);

	/* Iterate an empty qp-trie (Error) */
	bpf_dynptr_user_init(&key, sizeof(key), &dynptr);
	err = bpf_map_get_next_key(fd, NULL, &dynptr);
	CHECK(err != -ENOENT, "non-empty qp-trie", "error %d\n", err);

	close(fd);
}

static void test_qp_trie_bad_lookup_delete(void)
{
	struct bpf_dynptr_user dynptr;
	unsigned int key, value;
	int fd, err;

	fd = qp_trie_create(sizeof(key), sizeof(value), 2);

	/* Lookup/Delete non-existent key (Error) */
	key = 0;
	bpf_dynptr_user_init(&key, sizeof(key), &dynptr);
	err = bpf_map_delete_elem(fd, &dynptr);
	CHECK(err != -ENOENT, "del non-existent key", "error %d\n", err);
	err = bpf_map_lookup_elem(fd, &dynptr, &value);
	CHECK(err != -ENOENT, "lookup non-existent key", "error %d\n", err);

	key = 0;
	value = 2;
	bpf_dynptr_user_init(&key, 2, &dynptr);
	err = bpf_map_update_elem(fd, &dynptr, &value, BPF_NOEXIST);
	CHECK(err, "add elem", "error %d\n", err);

	key = 0;
	value = 4;
	bpf_dynptr_user_init(&key, sizeof(key), &dynptr);
	err = bpf_map_update_elem(fd, &dynptr, &value, BPF_NOEXIST);
	CHECK(err, "add elem", "error %d\n", err);

	/*
	 * Lookup/Delete non-existent key, although it is the prefix of
	 * existent keys (Error)
	 */
	key = 0;
	bpf_dynptr_user_init(&key, 1, &dynptr);
	err = bpf_map_delete_elem(fd, &dynptr);
	CHECK(err != -ENOENT, "del non-existent key", "error %d\n", err);
	err = bpf_map_lookup_elem(fd, &dynptr, &value);
	CHECK(err != -ENOENT, "lookup non-existent key", "error %d\n", err);

	/* Lookup/Delete non-existent key, although its prefix exists (Error) */
	key = 0;
	bpf_dynptr_user_init(&key, 3, &dynptr);
	err = bpf_map_delete_elem(fd, &dynptr);
	CHECK(err != -ENOENT, "del non-existent key", "error %d\n", err);
	err = bpf_map_lookup_elem(fd, &dynptr, &value);
	CHECK(err != -ENOENT, "lookup non-existent key", "error %d\n", err);

	close(fd);
}

static int cmp_str(const void *a, const void *b)
{
	const char *str_a = *(const char **)a, *str_b = *(const char **)b;

	return strcmp(str_a, str_b);
}

static void test_qp_trie_one_subtree_update(void)
{
	const char *keys[] = {
		"ab", "abc", "abo", "abS", "abcd",
	};
	const char *sorted_keys[ARRAY_SIZE(keys)];
	unsigned int value, got, i, j;
	struct bpf_dynptr_user dynptr;
	struct bpf_dynptr_user *cur;
	char data[4];
	int fd, err;

	fd = qp_trie_create(4, sizeof(value), ARRAY_SIZE(keys));

	for (i = 0; i < ARRAY_SIZE(keys); i++) {
		unsigned int flags;

		/* Add i-th element */
		flags = i % 2 ? BPF_NOEXIST : 0;
		bpf_dynptr_user_init((void *)keys[i], strlen(keys[i]), &dynptr);
		value = i + 100;
		err = bpf_map_update_elem(fd, &dynptr, &value, flags);
		CHECK(err, "add elem", "#%u error %d\n", i, err);

		err = bpf_map_lookup_elem(fd, &dynptr, &got);
		CHECK(err, "lookup elem", "#%u error %d\n", i, err);
		CHECK(got != value, "lookup elem", "#%u expect %u got %u\n", i, value, got);

		/* Re-add i-th element (Error) */
		err = bpf_map_update_elem(fd, &dynptr, &value, BPF_NOEXIST);
		CHECK(err != -EEXIST, "re-add elem", "#%u error %d\n", i, err);

		/* Overwrite i-th element */
		flags = i % 2 ? 0 : BPF_EXIST;
		value = i;
		err = bpf_map_update_elem(fd, &dynptr, &value, flags);
		CHECK(err, "update elem", "error %d\n", err);

		/* Lookup #[0~i] elements */
		for (j = 0; j <= i; j++) {
			bpf_dynptr_user_init((void *)keys[j], strlen(keys[j]), &dynptr);
			err = bpf_map_lookup_elem(fd, &dynptr, &got);
			CHECK(err, "lookup elem", "#%u/%u error %d\n", i, j, err);
			CHECK(got != j, "lookup elem", "#%u/%u expect %u got %u\n", i, j, value, got);
		}
	}

	/* Add element to a full qp-trie (Error) */
	memset(data, 0, sizeof(data));
	bpf_dynptr_user_init(&data, sizeof(data), &dynptr);
	value = 0;
	err = bpf_map_update_elem(fd, &dynptr, &value, 0);
	CHECK(err != -ENOSPC, "add to full qp-trie", "error %d\n", err);

	/* Iterate sorted elements */
	cur = NULL;
	memcpy(sorted_keys, keys, sizeof(keys));
	qsort(sorted_keys, ARRAY_SIZE(sorted_keys), sizeof(sorted_keys[0]), cmp_str);
	bpf_dynptr_user_init(data, sizeof(data), &dynptr);
	for (i = 0; i < ARRAY_SIZE(sorted_keys); i++) {
		unsigned int len;
		char *got;

		len = strlen(sorted_keys[i]);
		err = bpf_map_get_next_key(fd, cur, &dynptr);
		CHECK(err, "iterate", "#%u error %d\n", i, err);
		CHECK(bpf_dynptr_user_get_size(&dynptr) != len, "iterate",
		      "#%u invalid len %u expect %u\n",
		      i, bpf_dynptr_user_get_size(&dynptr), len);
		got = bpf_dynptr_user_get_data(&dynptr);
		CHECK(memcmp(sorted_keys[i], got, len), "iterate",
		      "#%u got %.*s exp %.*s\n", i, len, got, len, sorted_keys[i]);

		if (!cur)
			cur = &dynptr;
	}
	err = bpf_map_get_next_key(fd, cur, &dynptr);
	CHECK(err != -ENOENT, "more element", "error %d\n", err);

	/* Delete all elements */
	for (i = 0; i < ARRAY_SIZE(keys); i++) {
		bpf_dynptr_user_init((void *)keys[i], strlen(keys[i]), &dynptr);
		err = bpf_map_delete_elem(fd, &dynptr);
		CHECK(err, "del elem", "#%u elem error %d\n", i, err);

		/* Lookup deleted element (Error) */
		err = bpf_map_lookup_elem(fd, &dynptr, &got);
		CHECK(err != -ENOENT, "lookup elem", "#%u error %d\n", i, err);

		/* Lookup #(i~N] elements */
		for (j = i + 1; j < ARRAY_SIZE(keys); j++) {
			bpf_dynptr_user_init((void *)keys[j], strlen(keys[j]), &dynptr);
			err = bpf_map_lookup_elem(fd, &dynptr, &got);
			CHECK(err, "lookup elem", "#%u/%u error %d\n", i, j, err);
			CHECK(got != j, "lookup elem", "#%u/%u expect %u got %u\n", i, j, value, got);
		}
	}

	memset(data, 0, sizeof(data));
	bpf_dynptr_user_init(&data, sizeof(data), &dynptr);
	err = bpf_map_get_next_key(fd, NULL, &dynptr);
	CHECK(err != -ENOENT, "non-empty qp-trie", "error %d\n", err);

	close(fd);
}

static void test_qp_trie_all_subtree_update(void)
{
	unsigned int i, max_entries, key, value, got;
	struct bpf_dynptr_user dynptr;
	struct bpf_dynptr_user *cur;
	int fd, err;

	/* 16 elements per subtree */
	max_entries = 256 * 16;
	fd = qp_trie_create(sizeof(key), sizeof(value), max_entries);

	for (i = 0; i < max_entries; i++) {
		key = htole32(i);
		bpf_dynptr_user_init(&key, sizeof(key), &dynptr);
		value = i;
		err = bpf_map_update_elem(fd, &dynptr, &value, BPF_NOEXIST);
		CHECK(err, "add elem", "#%u error %d\n", i, err);

		err = bpf_map_lookup_elem(fd, &dynptr, &got);
		CHECK(err, "lookup elem", "#%u elem error %d\n", i, err);
		CHECK(got != value, "lookup elem", "#%u expect %u got %u\n", i, value, got);
	}

	/* Add element to a full qp-trie (Error) */
	key = htole32(max_entries + 1);
	bpf_dynptr_user_init(&key, sizeof(key), &dynptr);
	value = 0;
	err = bpf_map_update_elem(fd, &dynptr, &value, 0);
	CHECK(err != -ENOSPC, "add to full qp-trie", "error %d\n", err);

	/* Iterate all elements */
	cur = NULL;
	bpf_dynptr_user_init(&key, sizeof(key), &dynptr);
	for (i = 0; i < max_entries; i++) {
		unsigned int *data;
		unsigned int exp;

		exp = htole32((i / 16) | ((i & 0xf) << 8));
		err = bpf_map_get_next_key(fd, cur, &dynptr);
		CHECK(err, "iterate", "#%u error %d\n", i, err);
		CHECK(bpf_dynptr_user_get_size(&dynptr) != 4, "iterate",
		      "#%u invalid len %u\n", i, bpf_dynptr_user_get_size(&dynptr));
		data = bpf_dynptr_user_get_data(&dynptr);
		CHECK(data != &key, "dynptr data", "#%u got %p exp %p\n", i, data, &key);
		CHECK(key != exp, "iterate", "#%u got %u exp %u\n", i, key, exp);

		if (!cur)
			cur = &dynptr;
	}
	err = bpf_map_get_next_key(fd, cur, &dynptr);
	CHECK(err != -ENOENT, "more element", "error %d\n", err);

	/* Delete all elements */
	i = max_entries;
	while (i-- > 0) {
		key = i;
		bpf_dynptr_user_init(&key, sizeof(key), &dynptr);
		err = bpf_map_delete_elem(fd, &dynptr);
		CHECK(err, "del elem", "#%u error %d\n", i, err);

		/* Lookup deleted element (Error) */
		err = bpf_map_lookup_elem(fd, &dynptr, &got);
		CHECK(err != -ENOENT, "lookup elem", "#%u error %d\n", i, err);
	}

	bpf_dynptr_user_init(&key, sizeof(key), &dynptr);
	err = bpf_map_get_next_key(fd, NULL, &dynptr);
	CHECK(err != -ENOENT, "non-empty qp-trie", "error %d\n", err);

	close(fd);
}

static int binary_insert_data(unsigned int *set, unsigned int nr, unsigned int data)
{
	int begin = 0, end = nr - 1, mid, i;

	while (begin <= end) {
		mid = begin + (end - begin) / 2;
		if (data == set[mid])
			return -1;
		if (data > set[mid])
			begin = mid + 1;
		else
			end = mid - 1;
	}

	/* Move [begin, nr) backwards and insert new item at begin */
	i = nr - 1;
	while (i >= begin) {
		set[i + 1] = set[i];
		i--;
	}
	set[begin] = data;

	return 0;
}

/* UINT_MAX will not be in the returned data set */
static unsigned int *gen_random_unique_data_set(unsigned int max_entries)
{
	unsigned int *data_set;
	unsigned int i, data;

	data_set = malloc(sizeof(*data_set) * max_entries);
	CHECK(!data_set, "malloc", "no mem");

	for (i = 0; i < max_entries; i++) {
		while (true) {
			data = random() % UINT_MAX;
			if (!binary_insert_data(data_set, i, data))
				break;
		}
	}

	return data_set;
}

static int cmp_be32(const void *l, const void *r)
{
	unsigned int a = htobe32(*(unsigned int *)l), b = htobe32(*(unsigned int *)r);

	if (a < b)
		return -1;
	if (a > b)
		return 1;
	return 0;
}

static void test_qp_trie_rdonly_iterate(void)
{
	unsigned int i, max_entries, value, data, len;
	struct bpf_dynptr_user dynptr;
	struct bpf_dynptr_user *cur;
	unsigned int *data_set;
	int fd, err;

	max_entries = 4096;
	data_set = gen_random_unique_data_set(max_entries);
	qsort(data_set, max_entries, sizeof(*data_set), cmp_be32);

	fd = qp_trie_create(sizeof(*data_set), sizeof(value), max_entries);
	value = 1;
	for (i = 0; i < max_entries; i++) {
		bpf_dynptr_user_init(&data_set[i], sizeof(data_set[i]), &dynptr);
		err = bpf_map_update_elem(fd, &dynptr, &value, 0);
		CHECK(err, "add elem", "#%u error %d\n", i, err);
	}

	/* Iteration results are big-endian ordered */
	cur = NULL;
	bpf_dynptr_user_init(&data, sizeof(data), &dynptr);
	for (i = 0; i < max_entries; i++) {
		unsigned int *got;

		err = bpf_map_get_next_key(fd, cur, &dynptr);
		CHECK(err, "iterate", "#%u error %d\n", i, err);

		got = bpf_dynptr_user_get_data(&dynptr);
		len = bpf_dynptr_user_get_size(&dynptr);
		CHECK(len != 4, "iterate", "#%u invalid len %u\n", i, len);
		CHECK(got != &data, "iterate", "#%u invalid dynptr got %p exp %p\n", i, got, &data);
		CHECK(*got != data_set[i], "iterate", "#%u got 0x%x exp 0x%x\n",
		      i, *got, data_set[i]);
		cur = &dynptr;
	}
	err = bpf_map_get_next_key(fd, cur, &dynptr);
	CHECK(err != -ENOENT, "more element", "error %d\n", err);

	/* Iterate from non-existent key */
	data = htobe32(UINT_MAX);
	bpf_dynptr_user_init(&data, sizeof(data), &dynptr);
	err = bpf_map_get_next_key(fd, &dynptr, &dynptr);
	CHECK(err, "iterate from non-existent", "error %d\n", err);
	len = bpf_dynptr_user_get_size(&dynptr);
	CHECK(len != 4, "iterate", "invalid len %u\n", len);
	CHECK(data != data_set[0], "iterate", "got 0x%x exp 0x%x\n",
	      data, data_set[0]);

	free(data_set);

	close(fd);
}

/*
 * Delete current key (also the smallest key) after iteration, the next
 * iteration will return the second smallest key, so the iteration result
 * is still ordered.
 */
static void test_qp_trie_iterate_then_delete(void)
{
	unsigned int i, max_entries, value, data, len;
	struct bpf_dynptr_user dynptr;
	struct bpf_dynptr_user *cur;
	unsigned int *data_set;
	int fd, err;

	max_entries = 4096;
	data_set = gen_random_unique_data_set(max_entries);
	qsort(data_set, max_entries, sizeof(*data_set), cmp_be32);

	fd = qp_trie_create(sizeof(*data_set), sizeof(value), max_entries);
	value = 1;
	for (i = 0; i < max_entries; i++) {
		bpf_dynptr_user_init(&data_set[i], sizeof(data_set[i]), &dynptr);
		err = bpf_map_update_elem(fd, &dynptr, &value, BPF_NOEXIST);
		CHECK(err, "add elem", "#%u error %d\n", i, err);
	}

	/* Iteration results are big-endian ordered */
	cur = NULL;
	bpf_dynptr_user_init(&data, sizeof(data), &dynptr);
	for (i = 0; i < max_entries; i++) {
		err = bpf_map_get_next_key(fd, cur, &dynptr);
		CHECK(err, "iterate", "#%u error %d\n", i, err);

		len = bpf_dynptr_user_get_size(&dynptr);
		CHECK(len != 4, "iterate", "#%u invalid len %u\n", i, len);
		CHECK(data != data_set[i], "iterate", "#%u got 0x%x exp 0x%x\n",
		      i, data, data_set[i]);
		cur = &dynptr;

		/*
		 * Delete the mininal key, next call of bpf_get_next_key() will
		 * return the second minimal key.
		 */
		err = bpf_map_delete_elem(fd, &dynptr);
		CHECK(err, "del elem", "#%u elem error %d\n", i, err);
	}
	err = bpf_map_get_next_key(fd, cur, &dynptr);
	CHECK(err != -ENOENT, "more element", "error %d\n", err);

	err = bpf_map_get_next_key(fd, NULL, &dynptr);
	CHECK(err != -ENOENT, "no-empty qp-trie", "error %d\n", err);

	free(data_set);

	close(fd);
}

/* The range is half-closed: [from, to) */
static void delete_random_keys_in_range(int fd, unsigned int *data_set,
					unsigned int from, unsigned int to)
{
	unsigned int del_from, del_to;

	if (from >= to)
		return;

	del_from = random() % (to - from) + from;
	del_to = random() % (to - del_from) + del_from;
	for (; del_from <= del_to; del_from++) {
		struct bpf_dynptr_user dynptr;
		int err;

		/* Skip deleted keys */
		if (data_set[del_from] == UINT_MAX)
			continue;

		bpf_dynptr_user_init(&data_set[del_from], sizeof(data_set[del_from]), &dynptr);
		err = bpf_map_delete_elem(fd, &dynptr);
		CHECK(err, "del elem", "#%u range %u-%u error %d\n", del_from, from, to, err);
		data_set[del_from] = UINT_MAX;
	}
}

/* Delete keys randomly and ensure the iteration returns the expected data */
static void test_qp_trie_iterate_then_batch_delete(void)
{
	unsigned int i, max_entries, value, data, len;
	struct bpf_dynptr_user dynptr;
	struct bpf_dynptr_user *cur;
	unsigned int *data_set;
	int fd, err;

	max_entries = 8192;
	data_set = gen_random_unique_data_set(max_entries);
	qsort(data_set, max_entries, sizeof(*data_set), cmp_be32);

	fd = qp_trie_create(sizeof(*data_set), sizeof(value), max_entries);
	value = 1;
	for (i = 0; i < max_entries; i++) {
		bpf_dynptr_user_init(&data_set[i], sizeof(data_set[i]), &dynptr);
		err = bpf_map_update_elem(fd, &dynptr, &value, BPF_NOEXIST);
		CHECK(err, "add elem", "#%u error %d\n", i, err);
	}

	cur = NULL;
	bpf_dynptr_user_init(&data, sizeof(data), &dynptr);
	for (i = 0; i < max_entries; i++) {
		err = bpf_map_get_next_key(fd, cur, &dynptr);
		CHECK(err, "iterate", "#%u error %d\n", i, err);

		len = bpf_dynptr_user_get_size(&dynptr);
		CHECK(len != 4, "iterate", "#%u invalid len %u\n", i, len);
		CHECK(data != data_set[i], "iterate", "#%u got 0x%x exp 0x%x\n",
		      i, data, data_set[i]);
		cur = &dynptr;

		/* Delete some keys from iterated keys */
		delete_random_keys_in_range(fd, data_set, 0, i);

		/* Skip deleted keys */
		while (i + 1 < max_entries) {
			if (data_set[i + 1] != UINT_MAX)
				break;
			i++;
		}

		/* Delete some keys from to-iterate keys */
		delete_random_keys_in_range(fd, data_set, i + 1, max_entries);

		/* Skip deleted keys */
		while (i + 1 < max_entries) {
			if (data_set[i + 1] != UINT_MAX)
				break;
			i++;
		}
	}
	err = bpf_map_get_next_key(fd, cur, &dynptr);
	CHECK(err != -ENOENT, "more element", "error %d\n", err);

	free(data_set);

	close(fd);
}

/*
 * Add keys with odd index first and add keys with even index during iteration.
 * Check whether or not the whole key set is returned by iteration procedure.
 */
static void test_qp_trie_iterate_then_add(void)
{
	unsigned int i, max_entries, value, data, len;
	struct bpf_dynptr_user dynptr, next_key;
	struct bpf_dynptr_user *cur;
	unsigned int *data_set;
	int fd, err;

	max_entries = 8192;
	data_set = gen_random_unique_data_set(max_entries);
	qsort(data_set, max_entries, sizeof(*data_set), cmp_be32);

	fd = qp_trie_create(sizeof(*data_set), sizeof(value), max_entries);
	value = 1;
	for (i = 0; i < max_entries; i++) {
		if (i & 1)
			continue;

		bpf_dynptr_user_init(&data_set[i], sizeof(data_set[i]), &dynptr);
		err = bpf_map_update_elem(fd, &dynptr, &value, BPF_NOEXIST);
		CHECK(err, "add elem", "#%u error %d\n", i, err);
	}

	/* Iteration results are big-endian ordered */
	cur = NULL;
	bpf_dynptr_user_init(&data, sizeof(data), &next_key);
	for (i = 0; i < max_entries; i++) {
		err = bpf_map_get_next_key(fd, cur, &next_key);
		CHECK(err, "iterate", "#%u error %d\n", i, err);

		len = bpf_dynptr_user_get_size(&next_key);
		CHECK(len != 4, "iterate", "#%u invalid len %u\n", i, len);
		CHECK(data != data_set[i], "iterate", "#%u got 0x%x exp 0x%x\n",
		      i, data, data_set[i]);
		cur = &next_key;

		if ((i & 1) || i + 1 >= max_entries)
			continue;

		/* Add key with odd index which be returned in next iteration */
		bpf_dynptr_user_init(&data_set[i + 1], sizeof(data_set[i + 1]), &dynptr);
		err = bpf_map_update_elem(fd, &dynptr, &value, BPF_NOEXIST);
		CHECK(err, "add elem", "#%u error %d\n", i + 1, err);
	}
	err = bpf_map_get_next_key(fd, cur, &next_key);
	CHECK(err != -ENOENT, "more element", "error %d\n", err);

	free(data_set);

	close(fd);
}

static int get_int_from_env(const char *key, int dft)
{
	const char *value = getenv(key);

	if (!value)
		return dft;
	return atoi(value);
}

static void free_bytes_set(struct bpf_dynptr_user *set, unsigned int nr)
{
	unsigned int i;

	for (i = 0; i < nr; i++)
		free(bpf_dynptr_user_get_data(&set[i]));
	free(set);
}

struct bpf_dynptr_user *generate_random_bytes_set(unsigned int max_key_len, unsigned int nr)
{
	struct bpf_dynptr_user *set;
	unsigned int i;

	set = malloc(nr * sizeof(*set));
	CHECK(!set, "malloc", "no mem for set");

	for (i = 0; i < nr; i++) {
		unsigned char *data;
		unsigned int len, j;

		len = random() % max_key_len + 1;
		data = malloc(len);
		CHECK(!data, "maloc", "no mem for data");

		j = 0;
		while (j + 4 <= len) {
			unsigned int rnd = random();

			memcpy(&data[j], &rnd, sizeof(rnd));
			j += 4;
		}
		while (j < len)
			data[j++] = random();

		bpf_dynptr_user_init(data, len, &set[i]);
	}

	return set;
}

static struct bpf_dynptr_user *alloc_dynptr_user(unsigned int len)
{
	struct bpf_dynptr_user *dynptr;

	dynptr = malloc(sizeof(*dynptr) + len);
	if (!dynptr)
		return NULL;

	bpf_dynptr_user_init(&dynptr[1], len, dynptr);

	return dynptr;
}

static int cmp_dynptr_user(const struct bpf_dynptr_user *a, const struct bpf_dynptr_user *b)
{
	unsigned int a_len = bpf_dynptr_user_get_size(a), b_len = bpf_dynptr_user_get_size(b);
	unsigned int cmp = a_len < b_len ? a_len : b_len;
	int ret;

	ret = memcmp(bpf_dynptr_user_get_data(a), bpf_dynptr_user_get_data(b), cmp);
	if (ret)
		return ret;
	return a_len - b_len;
}

static void dump_dynptr_user(const char *name, const struct bpf_dynptr_user *ptr)
{
	unsigned char *data = bpf_dynptr_user_get_data(ptr);
	unsigned int i, len = bpf_dynptr_user_get_size(ptr);

	fprintf(stderr, "%s dynptr len %u data %p\n", name, len, data);

	for (i = 0; i < len; i++) {
		fprintf(stderr, "%02x ", data[i]);
		if (i % 16 == 15)
			fprintf(stderr, "\n");
	}
	fprintf(stderr, "\n");
}

static void copy_and_reset_dynptr_user(struct bpf_dynptr_user *dst_ptr,
				       struct bpf_dynptr_user *src_ptr, unsigned int reset_len)
{
	unsigned char *dst = bpf_dynptr_user_get_data(dst_ptr);
	unsigned char *src = bpf_dynptr_user_get_data(src_ptr);
	unsigned int src_len = bpf_dynptr_user_get_size(src_ptr);

	memcpy(dst, src, src_len);
	bpf_dynptr_user_init(dst, src_len, dst_ptr);
	bpf_dynptr_user_init(src, reset_len, src_ptr);
}

static void *update_fn(void *arg)
{
	const struct qp_trie_rw_ctx *ctx = arg;
	unsigned int i, j;

	for (i = 0; i < ctx->loop; i++) {
		for (j = 0; j < ctx->nr; j++) {
			unsigned int value;
			int err;

			value = bpf_dynptr_user_get_size(&ctx->set[i]);
			err = bpf_map_update_elem(ctx->fd, &ctx->set[i], &value, BPF_ANY);
			if (err) {
				fprintf(stderr, "update #%u element error %d\n", j, err);
				return (void *)(long)err;
			}
		}
	}

	return NULL;
}

static void *delete_fn(void *arg)
{
	const struct qp_trie_rw_ctx *ctx = arg;
	unsigned int i, j;

	for (i = 0; i < ctx->loop; i++) {
		for (j = 0; j < ctx->nr; j++) {
			int err;

			err = bpf_map_delete_elem(ctx->fd, &ctx->set[i]);
			if (err && err != -ENOENT) {
				fprintf(stderr, "delete #%u element error %d\n", j, err);
				return (void *)(long)err;
			}
		}
	}

	return NULL;
}

static void *lookup_fn(void *arg)
{
	const struct qp_trie_rw_ctx *ctx = arg;
	unsigned int i, j;

	for (i = 0; i < ctx->loop; i++) {
		for (j = 0; j < ctx->nr; j++) {
			unsigned int got, value;
			int err;

			got = 0;
			value = bpf_dynptr_user_get_size(&ctx->set[i]);
			err = bpf_map_lookup_elem(ctx->fd, &ctx->set[i], &got);
			if (!err && got != value) {
				fprintf(stderr, "lookup #%u element got %u expected %u\n", j, got, value);
				return (void *)(long)err;
			} else if (err && err != -ENOENT) {
				fprintf(stderr, "lookup #%u element error %d\n", j, err);
				return (void *)(long)err;
			}
		}
	}

	return NULL;
}

static void *iterate_fn(void *arg)
{
	const struct qp_trie_rw_ctx *ctx = arg;
	struct bpf_dynptr_user *key, *next_key;
	unsigned int i;
	int err;

	key = NULL;
	next_key = alloc_dynptr_user(ctx->max_key_len);
	if (!next_key)
		return (void *)(long)-ENOMEM;

	err = 0;
	for (i = 0; i < ctx->loop; i++) {
		while (true) {
			err = bpf_map_get_next_key(ctx->fd, key, next_key);
			if (err < 0) {
				if (err != -ENOENT) {
					fprintf(stderr, "get key error %d\n", err);
					goto out;
				}
				err = 0;
				break;
			}

			/* If no deletion, next key should be greater than key */
			if (!ctx->nr_delete && key && cmp_dynptr_user(key, next_key) >= 0) {
				fprintf(stderr, "unordered iteration result\n");
				dump_dynptr_user("previous key", key);
				dump_dynptr_user("cur key", next_key);
				err = -EINVAL;
				goto out;
			}

			if (!key) {
				key = alloc_dynptr_user(ctx->max_key_len);
				if (!key) {
					err = -ENOMEM;
					goto out;
				}
			}

			/* Copy next_key to key, and reset next_key */
			copy_and_reset_dynptr_user(key, next_key, ctx->max_key_len);
		}

		free(key);
		key = NULL;
	}

out:
	free(key);
	free(next_key);
	return (void *)(long)err;
}

static void do_qp_trie_stress_test(const struct stress_conf *conf)
{
	void *(*fns[MAX_OP])(void *arg) = {
		update_fn, delete_fn, lookup_fn, iterate_fn,
	};
	unsigned int created[MAX_OP];
	struct qp_trie_rw_ctx ctx;
	pthread_t *tids[MAX_OP];
	unsigned int op, i, err;

	ctx.nr = conf->nr;
	ctx.max_key_len = conf->max_key_len;
	ctx.fd = qp_trie_create(ctx.max_key_len, sizeof(unsigned int), ctx.nr);
	ctx.set = generate_random_bytes_set(ctx.max_key_len, ctx.nr);
	ctx.loop = conf->loop;
	ctx.nr_delete = conf->threads[DELETE_OP];

	/* Create threads */
	for (op = 0; op < ARRAY_SIZE(tids); op++) {
		if (!conf->threads[op]) {
			tids[op] = NULL;
			continue;
		}

		tids[op] = malloc(conf->threads[op] * sizeof(*tids[op]));
		CHECK(!tids[op], "malloc", "no mem for op %u threads %u\n", op, conf->threads[op]);
	}

	for (op = 0; op < ARRAY_SIZE(tids); op++) {
		for (i = 0; i < conf->threads[op]; i++) {
			err = pthread_create(&tids[op][i], NULL, fns[op], &ctx);
			if (err) {
				fprintf(stderr, "create #%u thread for op %u error %d\n", i, op, err);
				break;
			}
		}
		created[op] = i;
	}

	err = 0;
	for (op = 0; op < ARRAY_SIZE(tids); op++) {
		for (i = 0; i < created[op]; i++) {
			void *thread_err = NULL;

			pthread_join(tids[op][i], &thread_err);
			if (thread_err)
				err |= 1 << op;
		}
	}
	CHECK(err, "stress operation", "err %u\n", err);

	for (op = 0; op < ARRAY_SIZE(tids); op++)
		free(tids[op]);
	free_bytes_set(ctx.set, ctx.nr);
	close(ctx.fd);
}

static void test_qp_trie_stress(void)
{
	struct stress_conf conf;

	memset(&conf, 0, sizeof(conf));

	/* Test concurrently update, lookup and iterate operations. There is
	 * no deletion, so iteration can check the order of returned keys.
	 */
	conf.threads[UPDATE_OP] = get_int_from_env("QP_TRIE_NR_UPDATE", 8);
	conf.threads[LOOKUP_OP] = get_int_from_env("QP_TRIE_NR_LOOKUP", 8);
	conf.threads[ITERATE_OP] = get_int_from_env("QP_TRIE_NR_ITERATE", 8);
	conf.max_key_len = get_int_from_env("QP_TRIE_MAX_KEY_LEN", 256);
	conf.loop = get_int_from_env("QP_TRIE_NR_LOOP", 32);
	conf.nr = get_int_from_env("QP_TRIE_NR_DATA", 8192);
	do_qp_trie_stress_test(&conf);

	/* Add delete operation */
	conf.threads[DELETE_OP] = get_int_from_env("QP_TRIE_NR_DELETE", 8);
	do_qp_trie_stress_test(&conf);
}

void test_qp_trie_map(void)
{
	test_qp_trie_create();

	test_qp_trie_bad_update();

	test_qp_trie_bad_lookup_delete();

	test_qp_trie_one_subtree_update();

	test_qp_trie_all_subtree_update();

	test_qp_trie_rdonly_iterate();

	test_qp_trie_iterate_then_delete();

	test_qp_trie_iterate_then_batch_delete();

	test_qp_trie_iterate_then_add();

	test_qp_trie_stress();

	printf("%s:PASS\n", __func__);
}
