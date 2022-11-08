// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include "vma_build_id_parse.skel.h"

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
	if (!ASSERT_OK(err, "system"))
		goto out;

	f = fopen(tmp, "r");
	if (!ASSERT_OK_PTR(f, "fopen")) {
		err = -1;
		goto out;
	}
	if (fscanf(f, "%ms$*\n", build_id) != 1) {
		*build_id = NULL;
		err = -1;
	}
	fclose(f);
out:
	unlink(tmp);
	return err;
}

void test_vma_build_id_parse(void)
{
	char bpf_build_id[BPF_BUILD_ID_SIZE*2 + 1] = {}, *build_id;
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct vma_build_id_parse *skel;
	int i, err, prog_fd, size;

	skel = vma_build_id_parse__open_and_load();
	if (!ASSERT_OK_PTR(skel, "vma_build_id_parse__open_and_load"))
		return;

	skel->bss->target_pid = getpid();
	skel->bss->addr = (__u64)(uintptr_t)test_vma_build_id_parse;

	err = vma_build_id_parse__attach(skel);
	if (!ASSERT_OK(err, "vma_build_id_parse__attach"))
		goto out;

	prog_fd = bpf_program__fd(skel->progs.test1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	ASSERT_EQ(skel->data->find_addr_ret, 0, "find_addr_ret");
	ASSERT_GT(skel->data->vma_build_id_parse_ret, 0, "vma_build_id_parse_ret");

	if (!ASSERT_OK(read_buildid(&build_id), "read_buildid"))
		goto out;

	size = skel->data->vma_build_id_parse_ret;
	ASSERT_EQ(size, strlen(build_id)/2, "build_id_size");

	/* Convert bpf build id to string, so we can compare it. */
	for (i = 0; i < size; i++) {
		sprintf(bpf_build_id + i*2, "%02x",
			(unsigned char) skel->bss->build_id[i]);
	}
	ASSERT_STREQ(bpf_build_id, build_id, "build_ids_match");

	free(build_id);
out:
	vma_build_id_parse__destroy(skel);
}
