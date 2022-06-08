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

#include "test_verify_pkcs7_sig.skel.h"

#define MAX_DATA_SIZE 4096

struct data {
	u8 payload[MAX_DATA_SIZE];
};

static int populate_data_item(struct data *data_item)
{
	struct stat st;
	char signed_file_template[] = "/tmp/signed_fileXXXXXX";
	int ret, fd, child_status, child_pid;

	fd = mkstemp(signed_file_template);
	if (fd == -1)
		return -errno;

	ret = write(fd, "test", 4);

	close(fd);

	if (ret != 4) {
		ret = -EIO;
		goto out;
	}

	child_pid = fork();

	if (child_pid == -1) {
		ret = -errno;
		goto out;
	}

	if (child_pid == 0)
		return execlp(env.sign_file_path, env.sign_file_path, "sha256",
			      env.kernel_priv_cert_path,
			      env.kernel_priv_cert_path,
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

void test_verify_pkcs7_sig(void)
{
	struct test_verify_pkcs7_sig *skel = NULL;
	struct bpf_map *map;
	struct data data;
	u32 saved_len;
	int ret, zero = 0;

	if (!env.sign_file_path || !env.kernel_priv_cert_path) {
		printf(
		  "%s:SKIP:sign-file and kernel priv key cert paths missing\n",
		  __func__);
		test__skip();
		return;
	}

	skel = test_verify_pkcs7_sig__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_verify_pkcs7_sig__open_and_load"))
		goto close_prog;

	ret = test_verify_pkcs7_sig__attach(skel);
	if (!ASSERT_OK(ret, "test_verify_pkcs7_sig__attach\n"))
		goto close_prog;

	map = bpf_object__find_map_by_name(skel->obj, "data_input");
	if (!ASSERT_OK_PTR(map, "data_input not found"))
		goto close_prog;

	ret = populate_data_item(&data);
	if (!ASSERT_OK(ret, "populate_data_item\n"))
		goto close_prog;

	skel->bss->monitored_pid = getpid();

	ret = bpf_map_update_elem(bpf_map__fd(map), &zero, &data, BPF_ANY);
	if (!ASSERT_OK(ret, "bpf_map_update_elem\n"))
		goto close_prog;

	saved_len = *(__u32 *)data.payload;
	*(__u32 *)data.payload = sizeof(data.payload);
	ret = bpf_map_update_elem(bpf_map__fd(map), &zero, &data, BPF_ANY);
	if (!ASSERT_LT(ret, 0, "bpf_map_update_elem data_input\n"))
		goto close_prog;

	*(__u32 *)data.payload = saved_len;
	data.payload[sizeof(__u32)] = 'a';
	ret = bpf_map_update_elem(bpf_map__fd(map), &zero, &data, BPF_ANY);
	ASSERT_LT(ret, 0, "bpf_map_update_elem data_input\n");
close_prog:
	skel->bss->monitored_pid = 0;
	test_verify_pkcs7_sig__destroy(skel);
}
