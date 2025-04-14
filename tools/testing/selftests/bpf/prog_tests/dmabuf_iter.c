// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Google */

#include <test_progs.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include "dmabuf_iter.skel.h"

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <linux/dma-buf.h>
#include <linux/udmabuf.h>


static void subtest_dmabuf_iter_check_udmabuf(struct dmabuf_iter *skel)
{
	static const char test_buffer_name[] = "udmabuf_test_buffer_for_iter";
	const size_t test_buffer_size = 10 * getpagesize();

	ASSERT_LE(sizeof(test_buffer_name), DMA_BUF_NAME_LEN, "NAMETOOLONG");

	int memfd = memfd_create("memfd_test", MFD_ALLOW_SEALING);
	ASSERT_OK_FD(memfd, "memfd_create");

	ASSERT_OK(ftruncate(memfd, test_buffer_size), "ftruncate");

	ASSERT_OK(fcntl(memfd, F_ADD_SEALS, F_SEAL_SHRINK), "seal");

	int dev_udmabuf = open("/dev/udmabuf", O_RDONLY);
	ASSERT_OK_FD(dev_udmabuf, "open udmabuf");

	struct udmabuf_create create;
	create.memfd = memfd;
	create.flags = UDMABUF_FLAGS_CLOEXEC;
	create.offset = 0;
	create.size = test_buffer_size;

	int udmabuf = ioctl(dev_udmabuf, UDMABUF_CREATE, &create);
	close(dev_udmabuf);
	ASSERT_OK_FD(udmabuf, "udmabuf_create");

	ASSERT_OK(ioctl(udmabuf, DMA_BUF_SET_NAME_B, test_buffer_name), "name");

	int iter_fd = bpf_iter_create(bpf_link__fd(skel->links.dmabuf_collector));
	ASSERT_OK_FD(iter_fd, "iter_create");

	FILE *iter_file = fdopen(iter_fd, "r");
	ASSERT_OK_PTR(iter_file, "fdopen");

	char *line = NULL;
	size_t linesize = 0;
	bool found_test_udmabuf = false;
	while (getline(&line, &linesize, iter_file) != -1) {
		long inode, size;
		char name[DMA_BUF_NAME_LEN], exporter[32];

		int nelements = sscanf(line, "ino:%ld size:%ld name:%s exp_name:%s",
				       &inode, &size, name, exporter);

		if (nelements == 4 && size == test_buffer_size &&
				!strcmp(name, test_buffer_name) &&
				!strcmp(exporter, "udmabuf")) {
			found_test_udmabuf = true;
			break;
		}
	}

	ASSERT_TRUE(found_test_udmabuf, "found_test_buffer");

	free(line);
	fclose(iter_file);
	close(iter_fd);
	close(udmabuf);
	close(memfd);
}

void test_dmabuf_iter(void)
{
	struct dmabuf_iter *skel = NULL;
	char buf[256];
	int iter_fd;

	skel = dmabuf_iter__open_and_load();
	if (!ASSERT_OK_PTR(skel, "dmabuf_iter__open_and_load"))
		return;

	if (!ASSERT_OK(dmabuf_iter__attach(skel), "skel_attach"))
		goto destroy;

	iter_fd = bpf_iter_create(bpf_link__fd(skel->links.dmabuf_collector));
	if (!ASSERT_GE(iter_fd, 0, "iter_create"))
		goto destroy;

	memset(buf, 0, sizeof(buf));
	while (read(iter_fd, buf, sizeof(buf) > 0)) {
		/* Read out all contents */
	}

	/* Next reads should return 0 */
	ASSERT_EQ(read(iter_fd, buf, sizeof(buf)), 0, "read");

	if (test__start_subtest("check_udmabuf"))
		subtest_dmabuf_iter_check_udmabuf(skel);

	close(iter_fd);

destroy:
	dmabuf_iter__destroy(skel);
}
