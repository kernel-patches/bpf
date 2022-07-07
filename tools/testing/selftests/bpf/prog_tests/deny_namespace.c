// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <test_progs.h>
#include "test_deny_namespace.skel.h"
#include <sched.h>
#include "cap_helpers.h"

#define STACK_SIZE (1024 * 1024)
static char child_stack[STACK_SIZE];

int clone_callback(void *arg)
{
	return 0;
}

static int create_new_user_ns(void)
{
	int status;
	pid_t cpid;

	cpid = clone(clone_callback, child_stack + STACK_SIZE,
		     CLONE_NEWUSER | SIGCHLD, NULL);

	if (cpid == -1)
		return errno;

	if (cpid == 0)
		return 0;

	waitpid(cpid, &status, 0);
	if (WIFEXITED(status))
		return WEXITSTATUS(status);

	return -1;
}

static void test_create_user_ns_bpf(void)
{
	__u32 cap_mask = 1ULL << CAP_SYS_ADMIN;
	__u64 old_caps = 0;

	ASSERT_OK(create_new_user_ns(), "priv new user ns");

	cap_disable_effective(cap_mask, &old_caps);

	ASSERT_EQ(create_new_user_ns(), EPERM, "unpriv new user ns");

	if (cap_mask & old_caps)
		cap_enable_effective(cap_mask, NULL);
}

static void test_unpriv_create_user_ns_no_bpf(void)
{
	__u32 cap_mask = 1ULL << CAP_SYS_ADMIN;
	__u64 old_caps = 0;

	cap_disable_effective(cap_mask, &old_caps);

	ASSERT_OK(create_new_user_ns(), "no-bpf unpriv new user ns");

	if (cap_mask & old_caps)
		cap_enable_effective(cap_mask, NULL);
}

void test_deny_namespace(void)
{
	struct test_deny_namespace *skel = NULL;
	int err;

	if (test__start_subtest("unpriv_create_user_ns_no_bpf"))
		test_unpriv_create_user_ns_no_bpf();

	skel = test_deny_namespace__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel load"))
		goto close_prog;

	err = test_deny_namespace__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto close_prog;

	if (test__start_subtest("create_user_ns_bpf"))
		test_create_user_ns_bpf();

	test_deny_namespace__detach(skel);

close_prog:
	test_deny_namespace__destroy(skel);
}
