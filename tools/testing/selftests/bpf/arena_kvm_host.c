// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "arena_kvm_shared.h"

static int create_arena(const char *pin, int socket_fd, unsigned int pages)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts,
		.map_flags = BPF_F_MMAPABLE | BPF_F_ARENA_NO_FREE |
			     BPF_F_ARENA_EXPORT);
	char control[CMSG_SPACE(sizeof(int))] = {};
	char byte = 0;
	struct iovec iov = { .iov_base = &byte, .iov_len = 1 };
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	int fd, err = 1;

	fd = bpf_map_create(BPF_MAP_TYPE_ARENA, "arena_kvm", 0, 0,
			    pages, &opts);
	if (fd < 0) {
		if (errno == EOPNOTSUPP || errno == EINVAL)
			return 4; /* KSFT_SKIP: arena type or flags unsupported. */
		perror("create host arena");
		return 1;
	}
	if (bpf_obj_pin(fd, pin)) {
		perror("pin host arena");
		goto out;
	}
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
	if (sendmsg(socket_fd, &msg, 0) == 1)
		err = 0;
	else
		perror("send arena FD");
out:
	close(fd);
	return err;
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	struct bpf_map *arena, *bss;
	uint32_t key = 0, offset;
	unsigned long parsed;
	int fd, err;
	char *end;

	if (argc == 3 && !strcmp(argv[1], "--check-bpf")) {
		obj = bpf_object__open_file(argv[2], NULL);
		if (!obj)
			return 1;
		err = arena_kvm_check_features(obj);
		bpf_object__close(obj);
		return err;
	}

	if (argc == 2 && !strcmp(argv[1], "--check-kvm")) {
		fd = open("/dev/kvm", O_RDWR);
		if (fd < 0)
			return 4;
		err = ioctl(fd, KVM_GET_API_VERSION, 0);
		close(fd);
		return err == KVM_API_VERSION ? 0 : 4;
	}
	if (argc == 5 && !strcmp(argv[1], "--create")) {
		errno = 0;
		parsed = strtoul(argv[3], &end, 0);
		if (errno || *end || end == argv[3] || parsed > INT_MAX)
			return 1;
		fd = parsed;
		errno = 0;
		parsed = strtoul(argv[4], &end, 0);
		if (errno || *end || end == argv[4] || !parsed || parsed > UINT_MAX)
			return 1;
		return create_arena(argv[2], fd, parsed);
	}
	if (argc != 5)
		return 1;
	errno = 0;
	parsed = strtoul(argv[1], &end, 0);
	if (errno || *end || parsed > INT_MAX)
		return 1;
	fd = dup(parsed);
	if (fd < 0)
		return 1;
	errno = 0;
	parsed = strtoul(argv[3], &end, 0);
	if (errno || *end || parsed > UINT_MAX || parsed % getpagesize())
		goto fail;
	offset = parsed;
	obj = bpf_object__open_file(argv[2], NULL);
	if (!obj)
		goto fail;
	arena = bpf_object__find_map_by_name(obj, "arena");
	bss = bpf_object__find_map_by_name(obj, ".bss");
	prog = bpf_object__find_program_by_name(obj, argv[4]);
	if (!arena || !bss || !prog || bpf_map__reuse_fd(arena, fd))
		goto fail;
	if (offset >= (uint64_t)bpf_map__max_entries(arena) * getpagesize())
		goto fail;
	if (bpf_object__load(obj)) {
		fputs("load host BPF failed\n", stderr);
		goto fail;
	}
	if (bpf_map_update_elem(bpf_map__fd(bss), &key, &offset, BPF_ANY)) {
		perror("set signal offset");
		goto fail;
	}
	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	if (err)
		goto fail;
	printf("%u\n", opts.retval);
	bpf_object__close(obj);
	close(fd);
	return 0;

fail:
	bpf_object__close(obj);
	close(fd);
	return 1;
}
