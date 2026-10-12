// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 *
 * Guest helper for a BPF arena allocated from shared NUMA RAM.
 */
#define __EXPORTED_HEADERS__

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/mempolicy.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "arena_kvm_shared.h"

static int signal_file_offset(void *arena, uint64_t *offset)
{
	char cmdline[8192], *arg, *end;
	uint64_t entry, pfn, gpa, base = 0, size = 0, *value;
	ssize_t n;
	int fd, node, found = 0;

	/* The launcher supplies QEMU's guest physical base for this slice. */
	fd = open("/proc/cmdline", O_RDONLY);
	if (fd < 0)
		return -errno;
	n = read(fd, cmdline, sizeof(cmdline) - 1);
	close(fd);
	if (n <= 0 || n == sizeof(cmdline) - 1)
		return -EIO;
	cmdline[n] = '\0';
	for (arg = strtok(cmdline, "\n "); arg; arg = strtok(NULL, "\n ")) {
		if (!strncmp(arg, "arena_kvm.base=", 15)) {
			value = &base;
			found |= 1;
		} else if (!strncmp(arg, "arena_kvm.size=", 15)) {
			value = &size;
			found |= 2;
		} else {
			continue;
		}
		errno = 0;
		*value = strtoull(arg + 15, &end, 0);
		if (errno || *end || end == arg + 15 || *value % getpagesize())
			return -EINVAL;
	}
	if (found != 3 || size < getpagesize())
		return -EINVAL;

	/* Fault the BPF-allocated page into the guest user VMA. */
	if (!*(volatile uint64_t *)arena)
		return -EINVAL;
	if (syscall(SYS_get_mempolicy, &node, NULL, 0, arena,
		    MPOL_F_NODE | MPOL_F_ADDR))
		return -errno;
	if (node != ARENA_KVM_NODE)
		return -EXDEV;
	fd = open("/proc/self/pagemap", O_RDONLY);
	if (fd < 0)
		return -errno;
	n = pread(fd, &entry, sizeof(entry),
		  (uintptr_t)arena / getpagesize() * sizeof(entry));
	close(fd);
	if (n != sizeof(entry) || !(entry & (1ULL << 63)))
		return -EIO;
	pfn = entry & ((1ULL << 55) - 1);
	if (!pfn)
		return -EPERM;
	gpa = pfn * getpagesize();
	if (gpa < base || gpa - base >= size || size - (gpa - base) < getpagesize())
		return -ERANGE;
	*offset = gpa - base;
	return 0;
}

static int create_arena(void)
{
	union bpf_attr attr = {
		.map_type = BPF_MAP_TYPE_ARENA,
		.max_entries = 1,
		.map_flags = BPF_F_MMAPABLE | BPF_F_ARENA_NO_FREE,
	};

	return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int run_prog(int fd, unsigned int *retval)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err = bpf_prog_test_run_opts(fd, &opts);

	if (err)
		return err;
	*retval = opts.retval;
	return 0;
}

static int exchange_once(int fd)
{
	unsigned int result = 0;
	int err;

	/* The host bounds each protocol stage and stops the guest on timeout. */
	for (;;) {
		err = run_prog(fd, &result);
		if (err || result > 1)
			return err ? err : -EINVAL;
		if (!result)
			return 0;
		usleep(1000);
	}
}

int main(int argc, char **argv)
{
	struct bpf_object *obj = NULL;
	struct bpf_program *alloc, *probe_free, *exchange, *complete;
	struct bpf_map *map;
	void *arena = MAP_FAILED;
	uint64_t file_offset;
	unsigned int result = 0;
	int fd = -1;
	int err;

	setbuf(stdout, NULL);
	if (argc != 2 ||
	    (mount("sysfs", "/sys", "sysfs", 0, NULL) && errno != EBUSY) ||
	    (mount("proc", "/proc", "proc", 0, NULL) && errno != EBUSY))
		goto fail;
	if (access("/sys/devices/system/node/node1", F_OK)) {
		fputs("guest NUMA node 1 is unavailable\n", stderr);
		goto fail;
	}
	fd = create_arena();
	if (fd < 0) {
		perror("create guest arena");
		goto fail;
	}
	arena = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (arena == MAP_FAILED) {
		perror("mmap guest arena");
		goto fail;
	}
	obj = bpf_object__open_file(argv[1], NULL);
	if (!obj)
		goto fail;
	err = arena_kvm_check_features(obj);
	if (err == 4) {
		puts("GUEST_BPF_SKIPPED: compiler lacks arena address-space casts");
		bpf_object__close(obj);
		munmap(arena, getpagesize());
		close(fd);
		return 4;
	}
	if (err)
		goto fail;
	map = bpf_object__find_map_by_name(obj, "arena");
	alloc = bpf_object__find_program_by_name(obj, "allocate");
	probe_free = bpf_object__find_program_by_name(obj, "probe_free");
	exchange = bpf_object__find_program_by_name(obj, "exchange");
	complete = bpf_object__find_program_by_name(obj, "complete");
	if (!map || !alloc || !probe_free || !exchange || !complete ||
	    bpf_map__reuse_fd(map, fd))
		goto fail;
	close(fd);
	fd = -1;
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "load guest BPF: %d\n", err);
		goto fail;
	}
	err = run_prog(bpf_program__fd(alloc), &result);
	if (err || result) {
		fprintf(stderr, "allocate guest page: err=%d result=%u\n",
			err, result);
		goto fail;
	}
	err = run_prog(bpf_program__fd(probe_free), &result);
	if (err || result) {
		fprintf(stderr, "guest page lifetime check: err=%d result=%u\n",
			err, result);
		goto fail;
	}
	err = signal_file_offset(arena, &file_offset);
	if (err == -EXDEV) {
		puts("GUEST_BPF_SKIPPED: allocation fell back from shared NUMA node");
		bpf_object__close(obj);
		munmap(arena, getpagesize());
		return 4;
	}
	if (err) {
		fprintf(stderr, "resolve shared page offset: %d\n", err);
		goto fail;
	}
	printf("GUEST_BPF_READY %llu %d\n",
	       (unsigned long long)file_offset, getpagesize());
	if (exchange_once(bpf_program__fd(exchange)) ||
	    exchange_once(bpf_program__fd(exchange)) ||
	    exchange_once(bpf_program__fd(complete)))
		goto fail;
	puts("GUEST_BPF_EXCHANGED");
	bpf_object__close(obj);
	munmap(arena, getpagesize());
	return 0;

fail:
	puts("GUEST_BPF_FAILED");
	bpf_object__close(obj);
	if (arena != MAP_FAILED)
		munmap(arena, getpagesize());
	if (fd >= 0)
		close(fd);
	return 1;
}
