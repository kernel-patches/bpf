// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include <test_progs.h>
#include "test_perf_sample.skel.h"

#ifndef noinline
#define noinline __attribute__((noinline))
#endif

/* treat user-stack data as invalid (for testing only) */
#define PERF_SAMPLE_INVALID  PERF_SAMPLE_STACK_USER

#define PERF_MMAP_SIZE  8192
#define DATA_MMAP_SIZE  4096

static int perf_fd = -1;
static void *perf_ringbuf;
static struct test_perf_sample *skel;

static int open_perf_event(u64 sample_flags)
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_PAGE_FAULTS,
		.sample_type = sample_flags,
		.sample_period = 1,
		.disabled = 1,
		.size = sizeof(attr),
	};
	int fd;
	void *ptr;

	fd = syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
	if (!ASSERT_GT(fd, 0, "perf_event_open"))
		return -1;

	ptr = mmap(NULL, PERF_MMAP_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (!ASSERT_NEQ(ptr, MAP_FAILED, "mmap")) {
		close(fd);
		return -1;
	}

	perf_fd = fd;
	perf_ringbuf = ptr;

	return 0;
}

static void close_perf_event(void)
{
	if (perf_fd == -1)
		return;

	munmap(perf_ringbuf, PERF_MMAP_SIZE);
	close(perf_fd);

	perf_fd = -1;
	perf_ringbuf = NULL;
}

static noinline void trigger_perf_event(void)
{
	int *buf = mmap(NULL, DATA_MMAP_SIZE, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);

	if (!ASSERT_NEQ(buf, MAP_FAILED, "mmap"))
		return;

	ioctl(perf_fd, PERF_EVENT_IOC_ENABLE);

	/* it should generate a page fault which triggers the perf_event */
	*buf = 1;

	ioctl(perf_fd, PERF_EVENT_IOC_DISABLE);

	munmap(buf, DATA_MMAP_SIZE);
}

/* check if the perf ringbuf has a sample data */
static int check_perf_event(void)
{
	struct perf_event_mmap_page *page = perf_ringbuf;
	struct perf_event_header *hdr;

	if (page->data_head == page->data_tail)
		return 0;

	hdr = perf_ringbuf + page->data_offset;

	if (hdr->type != PERF_RECORD_SAMPLE)
		return 0;

	return 1;
}

static void setup_perf_sample_bpf_skel(u64 sample_flags)
{
	struct bpf_link *link;

	skel = test_perf_sample__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_perf_sample_open_and_load"))
		return;

	skel->bss->sample_flag = sample_flags;
	skel->bss->sample_size = sizeof(sample_flags);

	link = bpf_program__attach_perf_event(skel->progs.perf_sample_filter, perf_fd);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_perf_event"))
		return;
}

static void clean_perf_sample_bpf_skel(void)
{
	test_perf_sample__detach(skel);
	test_perf_sample__destroy(skel);
}

static void test_perf_event_read_sample_invalid(void)
{
	u64 flags = PERF_SAMPLE_INVALID;

	if (open_perf_event(flags) < 0)
		return;
	setup_perf_sample_bpf_skel(flags);
	trigger_perf_event();
	ASSERT_EQ(check_perf_event(), 0, "number of sample");
	clean_perf_sample_bpf_skel();
	close_perf_event();
}

static void test_perf_event_read_sample_ip(void)
{
	u64 flags = PERF_SAMPLE_IP;

	if (open_perf_event(flags) < 0)
		return;
	setup_perf_sample_bpf_skel(flags);
	trigger_perf_event();
	ASSERT_EQ(check_perf_event(), 1, "number of sample");
	clean_perf_sample_bpf_skel();
	close_perf_event();
}

static void test_perf_event_read_sample_addr(void)
{
	u64 flags = PERF_SAMPLE_ADDR;

	if (open_perf_event(flags) < 0)
		return;
	setup_perf_sample_bpf_skel(flags);
	trigger_perf_event();
	ASSERT_EQ(check_perf_event(), 1, "number of sample");
	clean_perf_sample_bpf_skel();
	close_perf_event();
}

void test_perf_event_read_sample(void)
{
	if (test__start_subtest("perf_event_read_sample_invalid"))
		test_perf_event_read_sample_invalid();
	if (test__start_subtest("perf_event_read_sample_ip"))
		test_perf_event_read_sample_ip();
	if (test__start_subtest("perf_event_read_sample_addr"))
		test_perf_event_read_sample_addr();
}
