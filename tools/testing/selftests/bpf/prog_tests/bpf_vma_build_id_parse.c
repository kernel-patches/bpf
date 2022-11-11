// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include "bpf_vma_build_id_parse.skel.h"

#define BUILDID_STR_SIZE (BPF_BUILD_ID_SIZE*2 + 1)

static int read_buildid(char **build_id)
{
	char tmp[] = "/tmp/dataXXXXXX";
	char buf[200];
	int err, fd;
	FILE *f;

	fd = mkstemp(tmp);
	if (fd == -1)
		return -1;
	close(fd);

	snprintf(buf, sizeof(buf),
		"readelf -n ./test_progs 2>/dev/null | grep 'Build ID' | awk '{print $3}' > %s",
		tmp);

	err = system(buf);
	if (err)
		goto out;

	f = fopen(tmp, "r");
	if (f) {
		if (fscanf(f, "%ms$*\n", build_id) != 1) {
			*build_id = NULL;
			err = -1;
		}
		fclose(f);
	}

out:
	unlink(tmp);
	return err;
}

void test_bpf_vma_build_id_parse(void)
{
	char bpf_build_id[BUILDID_STR_SIZE] = {}, *build_id;
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct bpf_vma_build_id_parse *skel;
	int i, err, prog_fd;

	skel = bpf_vma_build_id_parse__open_and_load();
	if (!ASSERT_OK_PTR(skel, "bpf_vma_build_id_parse__open_and_load"))
		return;

	skel->bss->target_pid = getpid();
	skel->bss->addr = (__u64)(uintptr_t)test_bpf_vma_build_id_parse;

	err = bpf_vma_build_id_parse__attach(skel);
	if (!ASSERT_OK(err, "bpf_vma_build_id_parse__attach"))
		goto out;

	prog_fd = bpf_program__fd(skel->progs.test1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run_err");
	ASSERT_EQ(topts.retval, 0, "test_run_retval");

	ASSERT_EQ(skel->data->ret, 0, "ret");

	ASSERT_GT(skel->data->size_pass, 0, "size_pass");
	ASSERT_EQ(skel->data->size_fail, -EINVAL, "size_fail");

	/* Read build id via readelf to compare with build_id. */
	if (!ASSERT_OK(read_buildid(&build_id), "read_buildid"))
		goto out;

	ASSERT_EQ(skel->data->size_pass, strlen(build_id)/2, "build_id_size");

	/* Convert bpf build id to string, so we can compare it later. */
	for (i = 0; i < skel->data->size_pass; i++) {
		sprintf(bpf_build_id + i*2, "%02x",
			(unsigned char) skel->bss->build_id[i]);
	}
	ASSERT_STREQ(bpf_build_id, build_id, "build_id_match");

	free(build_id);
out:
	bpf_vma_build_id_parse__destroy(skel);
}
