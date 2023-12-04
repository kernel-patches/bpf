// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <test_progs.h>
#include "test_perf_skip.skel.h"
#include <linux/hw_breakpoint.h>
#include <sys/mman.h>

#define BPF_OBJECT            "test_perf_skip.bpf.o"

static void handle_sig(int)
{
	ASSERT_OK(1, "perf event not skipped");
}

static noinline int test_function(void)
{
	return 0;
}

void serial_test_perf_skip(void)
{
	sighandler_t previous;
	int duration = 0;
	struct test_perf_skip *skel = NULL;
	int map_fd = -1;
	long page_size = sysconf(_SC_PAGE_SIZE);
	uintptr_t *ip = NULL;
	int prog_fd = -1;
	struct perf_event_attr attr = {0};
	int perf_fd = -1;
	struct f_owner_ex owner;
	int err;

	previous = signal(SIGIO, handle_sig);

	skel = test_perf_skip__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_load"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.handler);
	if (!ASSERT_OK(prog_fd < 0, "bpf_program__fd"))
		goto cleanup;

	map_fd = bpf_map__fd(skel->maps.ip);
	if (!ASSERT_OK(map_fd < 0, "bpf_map__fd"))
		goto cleanup;

	ip = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
	if (!ASSERT_OK_PTR(ip, "mmap bpf map"))
		goto cleanup;

	*ip = (uintptr_t)test_function;

	attr.type = PERF_TYPE_BREAKPOINT;
	attr.size = sizeof(attr);
	attr.bp_type = HW_BREAKPOINT_X;
	attr.bp_addr = (uintptr_t)test_function;
	attr.bp_len = sizeof(long);
	attr.sample_period = 1;
	attr.sample_type = PERF_SAMPLE_IP;
	attr.pinned = 1;
	attr.exclude_kernel = 1;
	attr.exclude_hv = 1;
	attr.precise_ip = 3;

	perf_fd = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
	if (CHECK(perf_fd < 0, "perf_event_open", "err %d\n", perf_fd))
		goto cleanup;

	err = fcntl(perf_fd, F_SETFL, O_ASYNC);
	if (!ASSERT_OK(err, "fcntl(F_SETFL, O_ASYNC)"))
		goto cleanup;

	owner.type = F_OWNER_TID;
	owner.pid = gettid();
	err = fcntl(perf_fd, F_SETOWN_EX, &owner);
	if (!ASSERT_OK(err, "fcntl(F_SETOWN_EX)"))
		goto cleanup;

	err = ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd);
	if (!ASSERT_OK(err, "ioctl(PERF_EVENT_IOC_SET_BPF)"))
		goto cleanup;

	test_function();

cleanup:
	if (perf_fd >= 0)
		close(perf_fd);
	if (ip)
		munmap(ip, page_size);
	if (skel)
		test_perf_skip__destroy(skel);

	signal(SIGIO, previous);
}
