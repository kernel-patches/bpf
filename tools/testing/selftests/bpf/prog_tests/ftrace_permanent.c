// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 CrowdStrike */
#include <test_progs.h>
#include "ftrace_permanent.skel.h"

/*
 * fentry/fexit/kprobe/kretprobe now carry FTRACE_OPS_FL_PERMANENT, so
 * kernel.ftrace_enabled=0 must be refused with EBUSY while any of them
 * is attached, and allowed again once detached.
 *
 * kprobe.multi/kretprobe.multi/kprobe.session are out of scope.
 * kprobe/kretprobe subtests need CONFIG_KPROBES_ON_FTRACE (e.g. not on
 * arm64) and are skipped otherwise.
 */

#define FTRACE_ENABLED_PATH "/proc/sys/kernel/ftrace_enabled"

static int read_ftrace_enabled(int *val)
{
	char buf[16] = {};
	int fd, n;

	fd = open(FTRACE_ENABLED_PATH, O_RDONLY);
	if (fd < 0)
		return -errno;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -EIO;
	*val = atoi(buf);
	return 0;
}

/* Returns 0 on success, or -errno on write failure. */
static int write_ftrace_enabled(int val)
{
	char buf[4];
	int fd, n, len, err = 0;

	fd = open(FTRACE_ENABLED_PATH, O_WRONLY);
	if (fd < 0)
		return -errno;
	len = snprintf(buf, sizeof(buf), "%d", val);
	n = write(fd, buf, len);
	if (n < 0)
		err = -errno;
	close(fd);
	return err;
}

/*
 * Attach @prog, assert kernel.ftrace_enabled=0 is refused while attached
 * and stays at 1, then detach and assert the disable now succeeds.
 */
static void check_blocks_disable(struct bpf_program *prog, const char *name)
{
	struct bpf_link *link;
	int val, err;

	link = bpf_program__attach(prog);
	if (!ASSERT_OK_PTR(link, name))
		return;

	err = write_ftrace_enabled(0);
	ASSERT_EQ(err, -EBUSY, "disable_refused");
	if (!ASSERT_OK(read_ftrace_enabled(&val), "read_back"))
		goto detach;
	ASSERT_EQ(val, 1, "still_enabled");

detach:
	bpf_link__destroy(link);

	ASSERT_OK(write_ftrace_enabled(0), "disable_after_detach");
	ASSERT_OK(write_ftrace_enabled(1), "reenable");
}

/* Attach @prog while ftrace_enabled=0 and assert it is refused. */
static void check_attach_while_disabled_refused(struct bpf_program *prog, const char *name)
{
	struct bpf_link *link;

	if (!ASSERT_OK(write_ftrace_enabled(0), "disable"))
		return;

	link = bpf_program__attach(prog);
	if (!ASSERT_ERR_PTR(link, name))
		bpf_link__destroy(link);

	ASSERT_OK(write_ftrace_enabled(1), "reenable");
}

void test_ftrace_permanent(void)
{
	struct ftrace_permanent *skel;
	bool kprobes_on_ftrace;
	int orig = 1;

	/* Save and always restore ftrace_enabled. */
	if (read_ftrace_enabled(&orig)) {
		test__skip();
		return;
	}

	skel = ftrace_permanent__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		goto restore;

	kprobes_on_ftrace = skel->kconfig->CONFIG_KPROBES_ON_FTRACE;

	if (test__start_subtest("fentry_blocks_disable"))
		check_blocks_disable(skel->progs.test_fentry, "attach_fentry");

	if (test__start_subtest("fexit_blocks_disable"))
		check_blocks_disable(skel->progs.test_fexit, "attach_fexit");

	if (test__start_subtest("kprobe_blocks_disable")) {
		if (kprobes_on_ftrace)
			check_blocks_disable(skel->progs.test_kprobe, "attach_kprobe");
		else
			test__skip();
	}

	if (test__start_subtest("kretprobe_blocks_disable")) {
		if (kprobes_on_ftrace)
			check_blocks_disable(skel->progs.test_kretprobe, "attach_kretprobe");
		else
			test__skip();
	}

	if (test__start_subtest("fentry_attach_while_disabled_refused"))
		check_attach_while_disabled_refused(skel->progs.test_fentry, "attach_fentry");

	if (test__start_subtest("kprobe_attach_while_disabled_refused")) {
		if (kprobes_on_ftrace)
			check_attach_while_disabled_refused(skel->progs.test_kprobe,
							    "attach_kprobe");
		else
			test__skip();
	}

	ftrace_permanent__destroy(skel);
restore:
	write_ftrace_enabled(orig);
}
