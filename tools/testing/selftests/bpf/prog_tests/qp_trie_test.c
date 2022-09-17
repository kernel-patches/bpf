// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2022. Huawei Technologies Co., Ltd */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <test_progs.h>
#include "qp_trie_test.skel.h"

static int setup_maps(struct qp_trie_test *skel, char *name, unsigned int value)
{
#define FILE_PATH_SIZE 64
	struct bpf_dynptr_user dynptr;
	char raw[FILE_PATH_SIZE];
	char zero;
	int fd, err;

	memset(raw, 0, sizeof(raw));
	strncpy(raw, name, sizeof(raw) - 1);

	fd = bpf_map__fd(skel->maps.trie);
	/* Full path returned from d_path includes the trailing terminator */
	bpf_dynptr_user_init(name, strlen(name) + 1, &dynptr);
	err = bpf_map_update_elem(fd, &dynptr, &value, BPF_NOEXIST);
	if (!ASSERT_OK(err, "trie add name"))
		return -EINVAL;

	zero = 0;
	bpf_dynptr_user_init(&zero, 1, &dynptr);
	err = bpf_map_update_elem(fd, &dynptr, &value, BPF_NOEXIST);
	if (!ASSERT_OK(err, "trie add zero"))
		return -EINVAL;

	fd = bpf_map__fd(skel->maps.htab);
	err = bpf_map_update_elem(fd, raw, &value, BPF_NOEXIST);
	if (!ASSERT_OK(err, "htab add"))
		return -EINVAL;

	return 0;
}

void test_qp_trie_test(void)
{
	char name[] = "/tmp/qp_trie_test";
	unsigned int value, new_value;
	struct bpf_dynptr_user dynptr;
	struct qp_trie_test *skel;
	int err, fd;
	char zero;

	skel = qp_trie_test__open();
	if (!ASSERT_OK_PTR(skel, "qp_trie_test__open()"))
		return;

	err = qp_trie_test__load(skel);
	if (!ASSERT_OK(err, "qp_trie_test__load()"))
		goto out;

	value = time(NULL);
	if (setup_maps(skel, name, value))
		goto out;

	skel->bss->pid = getpid();
	err = qp_trie_test__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto out;

	fd = open(name, O_RDONLY | O_CREAT, 0644);
	if (!ASSERT_GE(fd, 0, "open tmp file"))
		goto out;
	close(fd);
	unlink(name);

	ASSERT_EQ(skel->bss->trie_value, value, "trie lookup str");
	ASSERT_EQ(skel->bss->htab_value, -1, "htab lookup bytes");
	ASSERT_FALSE(skel->bss->zero_sized_key_bad, "zero-sized key");

	bpf_dynptr_user_init(name, strlen(name) + 1, &dynptr);
	new_value = 0;
	err = bpf_map_lookup_elem(bpf_map__fd(skel->maps.trie), &dynptr, &new_value);
	ASSERT_OK(err, "lookup elem");
	ASSERT_EQ(new_value, value + 1, "check new value");

	zero = 0;
	bpf_dynptr_user_init(&zero, 1, &dynptr);
	err = bpf_map_lookup_elem(bpf_map__fd(skel->maps.trie), &dynptr, &new_value);
	ASSERT_EQ(err, -ENOENT, "lookup deleted elem");

out:
	qp_trie_test__destroy(skel);
}
