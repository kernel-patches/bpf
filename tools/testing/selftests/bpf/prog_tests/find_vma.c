// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */
#include <test_progs.h>
#include <sys/types.h>
#include <unistd.h>
#include "find_vma.skel.h"

static void test_and_reset_skel(struct find_vma *skel, int expected_find_zero_ret)
{
	ASSERT_EQ(skel->bss->found_vm_exec, 1, "found_vm_exec");
	ASSERT_EQ(skel->data->find_addr_ret, 0, "find_addr_ret");
	ASSERT_EQ(skel->data->find_zero_ret, expected_find_zero_ret, "find_zero_ret");
	ASSERT_OK_PTR(strstr(skel->bss->d_iname, "test_progs"), "find_test_progs");

	skel->bss->found_vm_exec = 0;
	skel->data->find_addr_ret = -1;
	skel->data->find_zero_ret = -1;
	skel->bss->d_iname[0] = 0;
}

static int open_pe(void)
{
	struct perf_event_attr attr = {0};
	int pfd;

	/* create perf event */
	attr.size = sizeof(attr);
	attr.type = PERF_TYPE_HARDWARE;
	attr.config = PERF_COUNT_HW_CPU_CYCLES;
	attr.freq = 1;
	attr.sample_freq = 4000;
	pfd = syscall(__NR_perf_event_open, &attr, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);

	return pfd >= 0 ? pfd : -errno;
}

static void test_find_vma_pe(struct find_vma *skel)
{
	struct bpf_link *link = NULL;
	volatile int j = 0;
	int pfd = -1, i;

	pfd = open_pe();
	if (pfd < 0) {
		if (pfd == -ENOENT || pfd == -EOPNOTSUPP) {
			printf("%s:SKIP:no PERF_COUNT_HW_CPU_CYCLES\n", __func__);
			test__skip();
		}
		if (!ASSERT_GE(pfd, 0, "perf_event_open"))
			goto cleanup;
	}

	link = bpf_program__attach_perf_event(skel->progs.handle_pe, pfd);
	if (!ASSERT_OK_PTR(link, "attach_perf_event"))
		goto cleanup;

	for (i = 0; i < 1000000; ++i)
		++j;

	test_and_reset_skel(skel, -EBUSY /* in nmi, irq_work is busy */);
cleanup:
	bpf_link__destroy(link);
	close(pfd);
	/* caller will clean up skel */
}

static void test_find_vma_kprobe(struct find_vma *skel)
{
	int err;

	err = find_vma__attach(skel);
	if (!ASSERT_OK(err, "get_branch_snapshot__attach"))
		return;  /* caller will cleanup skel */

	getpgid(skel->bss->target_pid);
	test_and_reset_skel(skel, -ENOENT /* could not find vma for ptr 0 */);
}

void serial_test_find_vma(void)
{
	struct find_vma *skel;

	skel = find_vma__open_and_load();
	if (!ASSERT_OK_PTR(skel, "find_vma__open_and_load"))
		return;

	skel->bss->target_pid = getpid();
	skel->bss->addr = (__u64)test_find_vma_pe;

	test_find_vma_pe(skel);
	usleep(100000); /* allow the irq_work to finish */
	test_find_vma_kprobe(skel);

	find_vma__destroy(skel);
}
