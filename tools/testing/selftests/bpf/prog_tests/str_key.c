// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2022. Huawei Technologies Co., Ltd */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <test_progs.h>
#include "str_key.skel.h"

#define FILE_PATH_SIZE 64

struct file_path_str {
	unsigned int len;
	char raw[FILE_PATH_SIZE];
};

static int setup_maps(struct str_key *skel, const char *name, unsigned int value)
{
	struct file_path_str key;
	int fd, err;

	memset(&key, 0, sizeof(key));
	strncpy(key.raw, name, sizeof(key.raw) - 1);
	key.len = strlen(name) + 1;

	fd = bpf_map__fd(skel->maps.trie);
	err = bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST);
	if (!ASSERT_OK(err, "trie add"))
		return -EINVAL;

	fd = bpf_map__fd(skel->maps.htab);
	err = bpf_map_update_elem(fd, key.raw, &value, BPF_NOEXIST);
	if (!ASSERT_OK(err, "htab add"))
		return -EINVAL;

	return 0;
}

void test_str_key(void)
{
	const char *name = "/tmp/str_key_test";
	struct str_key *skel;
	unsigned int value;
	int err, fd;

	skel = str_key__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_load str key"))
		return;

	value = time(NULL);
	if (setup_maps(skel, name, value))
		goto out;

	skel->bss->pid = getpid();
	err = str_key__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto out;

	fd = open(name, O_RDONLY | O_CREAT, 0644);
	if (!ASSERT_GE(fd, 0, "open tmp file"))
		goto out;
	close(fd);
	unlink(name);

	ASSERT_EQ(skel->bss->trie_value, value, "trie lookup str");
	ASSERT_EQ(skel->bss->htab_value, -1, "htab lookup str");
out:
	str_key__destroy(skel);
}
