// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023 Yafang Shao <laoar.shao@gmail.com> */

#include <linux/perf_event.h>
#include <linux/bpf.h>
#include <test_progs.h>
#include "cap_helpers.h"
#include "test_bpf_current_cap.skel.h"

void serial_test_bpf_current_cap(void)
{
	struct test_bpf_current_cap *skel;
	struct perf_event_attr attr = {};
	int pfd, link_fd, err;
	__u64 caps = 0;

	skel = test_bpf_current_cap__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	attr.size = sizeof(attr);
	attr.type = PERF_TYPE_SOFTWARE;
	attr.config = PERF_COUNT_SW_CPU_CLOCK;
	attr.freq = 1;
	attr.sample_freq = 1000;
	pfd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
	if (!ASSERT_GE(pfd, 0, "perf_event_open"))
		goto cleanup;

	/* In case CAP_BPF and CAP_PERFMON is not set */
	err = cap_enable_effective(1ULL << CAP_BPF | 1ULL << CAP_PERFMON, &caps);
	if (!ASSERT_OK(err, "set_cap_bpf_perfmon"))
		goto close_perf;

	err = cap_disable_effective(1ULL << CAP_SYS_ADMIN, NULL);
	if (!ASSERT_OK(err, "disable_cap_sys_admin"))
		goto restore_cap;

	link_fd = bpf_link_create(bpf_program__fd(skel->progs.perf_event_run), pfd,
				  BPF_PERF_EVENT, NULL);
	if (!ASSERT_GE(link_fd, 0, "link_create_without_lsm"))
		goto restore_cap;
	close(link_fd);
	ASSERT_EQ(skel->bss->cap_sys_admin, false, "cap_sys_admin_init_value");
	ASSERT_EQ(skel->bss->cap_bpf, false, "cap_bpf_init_value");
	ASSERT_EQ(skel->bss->cap_perfmon, false, "cap_perfmon_init_value");

	skel->links.lsm_run = bpf_program__attach_lsm(skel->progs.lsm_run);
	if (!ASSERT_OK_PTR(skel->links.lsm_run, "lsm_attach"))
		goto restore_cap;

	link_fd = bpf_link_create(bpf_program__fd(skel->progs.perf_event_run), pfd,
				  BPF_PERF_EVENT, NULL);
	if (!ASSERT_LE(link_fd, 0, "link_create_without_sys_admin"))
		goto restore_cap;
	ASSERT_EQ(skel->bss->cap_sys_admin, false, "cap_sys_admin_disable");
	ASSERT_EQ(skel->bss->cap_bpf, true, "cap_bpf_enable");
	ASSERT_EQ(skel->bss->cap_perfmon, true, "cap_perfmon_enable");

	err = cap_enable_effective(1ULL << CAP_SYS_ADMIN, NULL);
	if (!ASSERT_OK(err, "enable_cap_sys_admin"))
		goto restore_cap;

	link_fd = bpf_link_create(bpf_program__fd(skel->progs.perf_event_run), pfd,
				  BPF_PERF_EVENT, NULL);
	if (!ASSERT_GE(link_fd, 0, "link_create_with_sys_admin"))
		goto restore_cap;
	close(link_fd);
	ASSERT_EQ(skel->bss->cap_sys_admin, true, "cap_sys_admin_enable");
	ASSERT_EQ(skel->bss->cap_bpf, true, "cap_bpf_enable");
	ASSERT_EQ(skel->bss->cap_perfmon, true, "cap_perfmon_enable");

restore_cap:
	if (caps)
		cap_enable_effective(caps, NULL);
close_perf:
	close(pfd);
cleanup:
	test_bpf_current_cap__destroy(skel);
}
