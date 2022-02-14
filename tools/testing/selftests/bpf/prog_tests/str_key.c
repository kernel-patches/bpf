// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2022. Huawei Technologies Co., Ltd */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <test_progs.h>
#include "str_key.skel.h"

#define HTAB_NAME_SIZE 64

struct str_htab_key {
	struct bpf_str_key_stor name;
	char raw[HTAB_NAME_SIZE];
};

static int setup_maps(struct str_key *skel, const char *name, unsigned int value)
{
	struct str_htab_key key;
	int fd, err;

	memset(&key, 0, sizeof(key));
	strncpy(key.raw, name, sizeof(key.raw) - 1);
	key.name.len = strlen(name) + 1;

	fd = bpf_map__fd(skel->maps.str_htab);
	err = bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST);
	if (!ASSERT_OK(err, "str htab add"))
		return -EINVAL;

	fd = bpf_map__fd(skel->maps.byte_htab);
	err = bpf_map_update_elem(fd, key.raw, &value, BPF_NOEXIST);
	if (!ASSERT_OK(err, "byte htab add"))
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

	srandom(time(NULL));
	value = random();
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

	ASSERT_EQ(skel->bss->str_htab_value, value, "str htab find");
	ASSERT_EQ(skel->bss->byte_htab_value, -1, "byte htab find");

out:
	str_key__destroy(skel);
}
