// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2022. Huawei Technologies Co., Ltd */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <test_progs.h>
#include "qp_trie_test.skel.h"

#define FILE_PATH_SIZE 64

static int setup_trie(struct bpf_map *trie, void *data, unsigned int size, unsigned int value)
{
	struct bpf_dynptr_user dynptr;
	char raw[FILE_PATH_SIZE];
	int fd, err, zero;

	fd = bpf_map__fd(trie);
	bpf_dynptr_user_init(data, size, &dynptr);
	err = bpf_map_update_elem(fd, &dynptr, &value, BPF_NOEXIST);
	if (!ASSERT_OK(err, "trie add data"))
		return -EINVAL;

	zero = 0;
	memset(raw, 0, size);
	bpf_dynptr_user_init(raw, size, &dynptr);
	err = bpf_map_update_elem(fd, &dynptr, &zero, BPF_NOEXIST);
	if (!ASSERT_OK(err, "trie add zero"))
		return -EINVAL;

	return 0;
}

static int setup_array(struct bpf_map *array, void *data, unsigned int size)
{
	char raw[FILE_PATH_SIZE];
	int fd, idx, err;

	fd = bpf_map__fd(array);

	idx = 0;
	memcpy(raw, data, size);
	memset(raw + size, 0, sizeof(raw) - size);
	err = bpf_map_update_elem(fd, &idx, raw, BPF_EXIST);
	if (!ASSERT_OK(err, "array add data"))
		return -EINVAL;

	idx = 1;
	memset(raw, 0, sizeof(raw));
	err = bpf_map_update_elem(fd, &idx, raw, BPF_EXIST);
	if (!ASSERT_OK(err, "array add zero"))
		return -EINVAL;

	return 0;
}

static int setup_htab(struct bpf_map *htab, void *data, unsigned int size, unsigned int value)
{
	char raw[FILE_PATH_SIZE];
	int fd, err;

	fd = bpf_map__fd(htab);

	memcpy(raw, data, size);
	memset(raw + size, 0, sizeof(raw) - size);
	err = bpf_map_update_elem(fd, &raw, &value, BPF_NOEXIST);
	if (!ASSERT_OK(err, "htab add data"))
		return -EINVAL;

	return 0;
}

static void test_qp_trie_basic_ops(void)
{
	const char *name = "qp_trie_basic_ops";
	unsigned int value, new_value;
	struct bpf_dynptr_user dynptr;
	struct qp_trie_test *skel;
	char raw[FILE_PATH_SIZE];
	int err;

	if (!ASSERT_LT(strlen(name), sizeof(raw), "lengthy data"))
		return;

	skel = qp_trie_test__open();
	if (!ASSERT_OK_PTR(skel, "qp_trie_test__open()"))
		return;

	bpf_program__set_autoload(skel->progs.basic_ops, true);

	err = qp_trie_test__load(skel);
	if (!ASSERT_OK(err, "qp_trie_test__load()"))
		goto out;

	value = time(NULL);
	if (setup_trie(skel->maps.trie, (void *)name, strlen(name), value))
		goto out;

	if (setup_array(skel->maps.array, (void *)name, strlen(name)))
		goto out;

	skel->bss->key_size = strlen(name);
	skel->bss->pid = getpid();
	err = qp_trie_test__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto out;

	usleep(1);

	ASSERT_EQ(skel->bss->lookup_str_value, -1, "trie lookup str");
	ASSERT_EQ(skel->bss->lookup_bytes_value, value, "trie lookup byte");
	ASSERT_EQ(skel->bss->delete_again_err, -ENOENT, "trie delete again");

	bpf_dynptr_user_init((void *)name, strlen(name), &dynptr);
	new_value = 0;
	err = bpf_map_lookup_elem(bpf_map__fd(skel->maps.trie), &dynptr, &new_value);
	ASSERT_OK(err, "lookup trie");
	ASSERT_EQ(new_value, value + 1, "check updated value");

	memset(raw, 0, sizeof(raw));
	bpf_dynptr_user_init(&raw, strlen(name), &dynptr);
	err = bpf_map_lookup_elem(bpf_map__fd(skel->maps.trie), &dynptr, &new_value);
	ASSERT_EQ(err, -ENOENT, "check deleted elem");
out:
	qp_trie_test__destroy(skel);
}

static void test_qp_trie_zero_size_dynptr(void)
{
	struct qp_trie_test *skel;
	int err;

	skel = qp_trie_test__open();
	if (!ASSERT_OK_PTR(skel, "qp_trie_test__open()"))
		return;

	bpf_program__set_autoload(skel->progs.zero_size_dynptr, true);

	err = qp_trie_test__load(skel);
	if (!ASSERT_OK(err, "qp_trie_test__load()"))
		goto out;

	skel->bss->pid = getpid();
	err = qp_trie_test__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto out;

	usleep(1);

	ASSERT_OK(skel->bss->zero_size_err, "handle zero sized dynptr");
out:
	qp_trie_test__destroy(skel);
}

static void test_qp_trie_d_path_key(void)
{
	const char *name = "/tmp/qp_trie_d_path_key";
	struct qp_trie_test *skel;
	char raw[FILE_PATH_SIZE];
	unsigned int value;
	int fd, err;

	if (!ASSERT_LT(strlen(name), sizeof(raw), "lengthy data"))
		return;

	skel = qp_trie_test__open();
	if (!ASSERT_OK_PTR(skel, "qp_trie_test__open()"))
		return;

	bpf_program__set_autoload(skel->progs.d_path_key, true);

	err = qp_trie_test__load(skel);
	if (!ASSERT_OK(err, "qp_trie_test__load()"))
		goto out;

	value = time(NULL);
	/* Include the trailing zero byte */
	if (setup_trie(skel->maps.trie, (void *)name, strlen(name) + 1, value))
		goto out;

	if (setup_htab(skel->maps.htab, (void *)name, strlen(name) + 1, value))
		goto out;

	skel->bss->pid = getpid();
	err = qp_trie_test__attach(skel);
	/* No support for bpf trampoline ? */
	if (err == -ENOTSUPP) {
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "attach"))
		goto out;

	fd = open(name, O_RDONLY | O_CREAT, 0644);
	if (!ASSERT_GT(fd, 0, "open tmp file"))
		goto out;
	close(fd);
	unlink(name);

	ASSERT_EQ(skel->bss->trie_path_value, value, "trie lookup");
	ASSERT_EQ(skel->bss->htab_path_value, -1, "htab lookup");
out:
	qp_trie_test__destroy(skel);
}

void test_qp_trie_test(void)
{
	if (test__start_subtest("basic_ops"))
		test_qp_trie_basic_ops();
	if (test__start_subtest("zero_size_dynptr"))
		test_qp_trie_zero_size_dynptr();
	if (test__start_subtest("d_path_key"))
		test_qp_trie_d_path_key();
}
