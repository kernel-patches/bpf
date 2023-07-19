// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023 Yafang Shao <laoar.shao@gmail.com> */

#include <string.h>
#include <linux/bpf.h>
#include <linux/limits.h>
#include <test_progs.h>
#include "trace_helpers.h"
#include "test_fill_link_info.skel.h"

#define TP_CAT "sched"
#define TP_NAME "sched_switch"
#define KPROBE_FUNC "tcp_rcv_established"
#define UPROBE_FILE "/proc/self/exe"

/* uprobe attach point */
static noinline void uprobe_func(void)
{
	asm volatile ("");
}

static int verify_link_info(int fd, enum bpf_perf_event_type type, long addr, ssize_t offset)
{
	struct bpf_link_info info;
	__u32 len = sizeof(info);
	char buf[PATH_MAX];
	int err = 0;

	memset(&info, 0, sizeof(info));
	buf[0] = '\0';

again:
	err = bpf_link_get_info_by_fd(fd, &info, &len);
	if (!ASSERT_OK(err, "get_link_info"))
		return -1;

	switch (info.type) {
	case BPF_LINK_TYPE_PERF_EVENT:
		if (!ASSERT_EQ(info.perf_event.type, type, "perf_type_match"))
			return -1;

		switch (info.perf_event.type) {
		case BPF_PERF_EVENT_KPROBE:
		case BPF_PERF_EVENT_KRETPROBE:
			ASSERT_EQ(info.perf_event.kprobe.offset, offset, "kprobe_offset");

			/* In case kptr setting is not permitted or MAX_SYMS is reached */
			if (addr) {
				long addrs[2] = {
					addr + offset,
					addr + 0x4, /* For ENDBDR */
				};

				ASSERT_IN_ARRAY(info.perf_event.kprobe.addr, addrs, "kprobe_addr");
			}

			if (!info.perf_event.kprobe.func_name) {
				ASSERT_EQ(info.perf_event.kprobe.name_len, 0, "name_len");
				info.perf_event.kprobe.func_name = ptr_to_u64(&buf);
				info.perf_event.kprobe.name_len = sizeof(buf);
				goto again;
			}

			err = strncmp(u64_to_ptr(info.perf_event.kprobe.func_name), KPROBE_FUNC,
				      strlen(KPROBE_FUNC));
			ASSERT_EQ(err, 0, "cmp_kprobe_func_name");
			break;
		case BPF_PERF_EVENT_TRACEPOINT:
			if (!info.perf_event.tracepoint.tp_name) {
				ASSERT_EQ(info.perf_event.tracepoint.name_len, 0, "name_len");
				info.perf_event.tracepoint.tp_name = ptr_to_u64(&buf);
				info.perf_event.tracepoint.name_len = sizeof(buf);
				goto again;
			}

			err = strncmp(u64_to_ptr(info.perf_event.tracepoint.tp_name), TP_NAME,
				      strlen(TP_NAME));
			ASSERT_EQ(err, 0, "cmp_tp_name");
			break;
		case BPF_PERF_EVENT_UPROBE:
		case BPF_PERF_EVENT_URETPROBE:
			ASSERT_EQ(info.perf_event.uprobe.offset, offset, "uprobe_offset");

			if (!info.perf_event.uprobe.file_name) {
				ASSERT_EQ(info.perf_event.uprobe.name_len, 0, "name_len");
				info.perf_event.uprobe.file_name = ptr_to_u64(&buf);
				info.perf_event.uprobe.name_len = sizeof(buf);
				goto again;
			}

			err = strncmp(u64_to_ptr(info.perf_event.uprobe.file_name), UPROBE_FILE,
				      strlen(UPROBE_FILE));
			ASSERT_EQ(err, 0, "cmp_file_name");
			break;
		default:
			break;
		}
		break;
	default:
		switch (type) {
		case BPF_PERF_EVENT_KPROBE:
		case BPF_PERF_EVENT_KRETPROBE:
		case BPF_PERF_EVENT_TRACEPOINT:
		case BPF_PERF_EVENT_UPROBE:
		case BPF_PERF_EVENT_URETPROBE:
			err = -1;
			break;
		default:
			break;
		}
		break;
	}
	return err;
}

static void kprobe_fill_invalid_user_buffer(int fd)
{
	struct bpf_link_info info;
	__u32 len = sizeof(info);
	int err = 0;

	memset(&info, 0, sizeof(info));

	info.perf_event.kprobe.func_name = 0x1; /* invalid address */
	err = bpf_link_get_info_by_fd(fd, &info, &len);
	ASSERT_EQ(err, -EINVAL, "invalid_buff_and_len");

	info.perf_event.kprobe.name_len = 64;
	err = bpf_link_get_info_by_fd(fd, &info, &len);
	ASSERT_EQ(err, -EFAULT, "invalid_buff");

	info.perf_event.kprobe.func_name = 0;
	err = bpf_link_get_info_by_fd(fd, &info, &len);
	ASSERT_EQ(err, -EINVAL, "invalid_len");

	ASSERT_EQ(info.perf_event.kprobe.addr, 0, "func_addr");
	ASSERT_EQ(info.perf_event.kprobe.offset, 0, "func_offset");
	ASSERT_EQ(info.perf_event.type, 0, "type");
}

static void test_kprobe_fill_link_info(struct test_fill_link_info *skel,
				       enum bpf_perf_event_type type,
				       bool retprobe, bool invalid)
{
	DECLARE_LIBBPF_OPTS(bpf_kprobe_opts, opts,
		.attach_mode = PROBE_ATTACH_MODE_LINK,
		.retprobe = retprobe,
	);
	int link_fd, err;
	long addr;

	skel->links.kprobe_run = bpf_program__attach_kprobe_opts(skel->progs.kprobe_run,
								 KPROBE_FUNC, &opts);
	if (!ASSERT_OK_PTR(skel->links.kprobe_run, "attach_kprobe"))
		return;

	link_fd = bpf_link__fd(skel->links.kprobe_run);
	if (!ASSERT_GE(link_fd, 0, "link_fd"))
		return;

	addr = ksym_get_addr(KPROBE_FUNC);
	if (!invalid) {
		err = verify_link_info(link_fd, type, addr, 0);
		ASSERT_OK(err, "verify_link_info");
	} else {
		kprobe_fill_invalid_user_buffer(link_fd);
	}
	bpf_link__detach(skel->links.kprobe_run);
}

static void test_tp_fill_link_info(struct test_fill_link_info *skel)
{
	int link_fd, err;

	skel->links.tp_run = bpf_program__attach_tracepoint(skel->progs.tp_run, TP_CAT, TP_NAME);
	if (!ASSERT_OK_PTR(skel->links.tp_run, "attach_tp"))
		return;

	link_fd = bpf_link__fd(skel->links.tp_run);
	if (!ASSERT_GE(link_fd, 0, "link_fd"))
		return;

	err = verify_link_info(link_fd, BPF_PERF_EVENT_TRACEPOINT, 0, 0);
	ASSERT_OK(err, "verify_link_info");
	bpf_link__detach(skel->links.tp_run);
}

static void test_uprobe_fill_link_info(struct test_fill_link_info *skel,
				       enum bpf_perf_event_type type, ssize_t offset,
				       bool retprobe)
{
	int link_fd, err;

	skel->links.uprobe_run = bpf_program__attach_uprobe(skel->progs.uprobe_run, retprobe,
							    0, /* self pid */
							    UPROBE_FILE, offset);
	if (!ASSERT_OK_PTR(skel->links.uprobe_run, "attach_uprobe"))
		return;

	link_fd = bpf_link__fd(skel->links.uprobe_run);
	if (!ASSERT_GE(link_fd, 0, "link_fd"))
		return;

	err = verify_link_info(link_fd, type, 0, offset);
	ASSERT_OK(err, "verify_link_info");
	bpf_link__detach(skel->links.uprobe_run);
}

void serial_test_fill_link_info(void)
{
	struct test_fill_link_info *skel;
	ssize_t offset;

	skel = test_fill_link_info__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	/* load kallsyms to compare the addr */
	if (!ASSERT_OK(load_kallsyms_refresh(), "load_kallsyms_refresh"))
		return;
	if (test__start_subtest("kprobe_link_info"))
		test_kprobe_fill_link_info(skel, BPF_PERF_EVENT_KPROBE, false, false);
	if (test__start_subtest("kretprobe_link_info"))
		test_kprobe_fill_link_info(skel, BPF_PERF_EVENT_KRETPROBE, true, false);
	if (test__start_subtest("fill_invalid_user_buff"))
		test_kprobe_fill_link_info(skel, BPF_PERF_EVENT_KPROBE, false, true);
	if (test__start_subtest("tracepoint_link_info"))
		test_tp_fill_link_info(skel);

	offset = get_uprobe_offset(&uprobe_func);
	if (test__start_subtest("uprobe_link_info"))
		test_uprobe_fill_link_info(skel, BPF_PERF_EVENT_UPROBE, offset, false);
	if (test__start_subtest("uretprobe_link_info"))
		test_uprobe_fill_link_info(skel, BPF_PERF_EVENT_URETPROBE, offset, true);

cleanup:
	test_fill_link_info__destroy(skel);
}
