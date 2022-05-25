// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <endian.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <test_progs.h>

#include "map_value_sig.skel.h"

#define MAX_DATA_SIZE 1024
#define ARRAY_ELEMS 5

struct data {
	u8 payload[MAX_DATA_SIZE];
};

struct data_info {
	char str[10];
	int str_len;
};

int populate_data_item(struct data *data_item, struct data_info *data_info_item)
{
	struct stat st;
	char signed_file_template[] = "/tmp/signed_fileXXXXXX";
	int ret, fd, child_status, child_pid;

	fd = mkstemp(signed_file_template);
	if (fd == -1) {
		ret = -errno;
		goto out;
	}

	ret = write(fd, data_info_item->str, data_info_item->str_len);

	close(fd);

	if (ret != data_info_item->str_len) {
		ret = -EIO;
		goto out;
	}

	child_pid = fork();

	if (child_pid == -1) {
		ret = -errno;
		goto out;
	}

	if (child_pid == 0)
		return execlp("../../../../scripts/sign-file",
			      "../../../../scripts/sign-file", "sha256",
			      "../../../../certs/signing_key.pem",
			      "../../../../certs/signing_key.pem",
			      signed_file_template, NULL);

	waitpid(child_pid, &child_status, 0);

	ret = WEXITSTATUS(child_status);
	if (ret)
		goto out;

	ret = stat(signed_file_template, &st);
	if (ret == -1) {
		ret = -errno;
		goto out;
	}

	if (st.st_size > sizeof(data_item->payload) - sizeof(u32)) {
		ret = -EINVAL;
		goto out;
	}

	*(u32 *)data_item->payload = __cpu_to_be32(st.st_size);

	fd = open(signed_file_template, O_RDONLY);
	if (fd == -1) {
		ret = -errno;
		goto out;
	}

	ret = read(fd, data_item->payload + sizeof(u32), st.st_size);

	close(fd);

	if (ret != st.st_size) {
		ret = -EIO;
		goto out;
	}

	ret = 0;
out:
	unlink(signed_file_template);
	return ret;
}

void test_test_map_value_sig(void)
{
	struct map_value_sig *skel = NULL;
	struct bpf_map *map;
	struct data *data_array = NULL;
	struct data_info *data_info_array = NULL;
	int keys[ARRAY_ELEMS];
	u32 max_entries = ARRAY_ELEMS;
	int ret, zero = 0, i, map_fd, duration = 0;

	DECLARE_LIBBPF_OPTS(bpf_map_create_opts, create_opts,
			    .map_flags = BPF_F_MMAPABLE | BPF_F_VERIFY_ELEM);

	DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
		.elem_flags = 0,
		.flags = 0,
	);

	data_array = malloc(sizeof(*data_array) * ARRAY_ELEMS);
	if (CHECK(!data_array, "data array", "not enough memory\n"))
		goto close_prog;

	data_info_array = malloc(sizeof(*data_info_array) * ARRAY_ELEMS);
	if (CHECK(!data_info_array, "data info array", "not enough memory\n"))
		goto close_prog;

	skel = map_value_sig__open_and_load();
	if (CHECK(!skel, "skel", "open_and_load failed\n"))
		goto close_prog;

	ret = map_value_sig__attach(skel);
	if (CHECK(ret < 0, "skel", "attach failed\n"))
		goto close_prog;

	map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, NULL, 4,
				sizeof(struct data), ARRAY_ELEMS, &create_opts);
	if (CHECK(map_fd != -EINVAL, "bpf_map_create",
		  "should fail (mmapable & verify_elem flags set\n"))
		goto close_prog;

	map = bpf_object__find_map_by_name(skel->obj, "data_input");
	if (CHECK(!map, "bpf_object__find_map_by_name", "not found\n"))
		goto close_prog;

	for (i = 0; i < ARRAY_ELEMS; i++) {
		keys[i] = i;

		data_info_array[i].str_len = snprintf(data_info_array[i].str,
						 sizeof(data_info_array[i].str),
						 "test%d", i);

		ret = populate_data_item(&data_array[i], &data_info_array[i]);
		if (CHECK(ret, "populate_data_item", "error: %d\n", ret))
			goto close_prog;

		ret = bpf_map_update_elem(bpf_map__fd(map), &zero,
					  &data_array[i], BPF_ANY);
		if (CHECK(ret < 0, "bpf_map_update_elem", "error: %d\n", ret))
			goto close_prog;

		if (CHECK(skel->bss->verified_data_size !=
			  data_info_array[i].str_len, "data size",
			  "mismatch\n"))
			goto close_prog;
	}

	ret = bpf_map_update_batch(bpf_map__fd(map), keys, (void *)data_array,
				   &max_entries, &opts);
	if (CHECK(ret, "bpf_map_update_batch", "error: %d\n", ret))
		goto close_prog;

	*(u32 *)data_array[0].payload =
				__cpu_to_be32(sizeof(data_array[0].payload));

	ret = bpf_map_update_elem(bpf_map__fd(map), &zero, &data_array[0],
				  BPF_ANY);
	if (CHECK(!ret, "bpf_map_update_elem", "should fail (invalid size)\n"))
		goto close_prog;

	ret = bpf_map_update_batch(bpf_map__fd(map), keys, (void *)data_array,
				   &max_entries, &opts);
	if (CHECK(!ret, "bpf_map_update_batch", "should fail (invalid size)\n"))
		goto close_prog;

	*(u32 *)data_array[0].payload =
				__cpu_to_be32(data_info_array[0].str_len);

	data_array[0].payload[sizeof(u32) + data_info_array[0].str_len - 1] =
									'\0';
	ret = bpf_map_update_elem(bpf_map__fd(map), &zero, &data_array[0], 0);
	if (CHECK(!ret, "bpf_map_update_elem",
		  "should fail (invalid signature)\n"))
		goto close_prog;

	max_entries = ARRAY_ELEMS;

	ret = bpf_map_update_batch(bpf_map__fd(map), keys, (void *)data_array,
				   &max_entries, &opts);
	if (CHECK(!ret, "bpf_map_update_batch",
		  "should fail (invalid signature)\n"))
		goto close_prog;
close_prog:
	map_value_sig__destroy(skel);
	free(data_array);
	free(data_info_array);
}
