// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <test_progs.h>
#include "test_deny_namespace.skel.h"
#include <sched.h>
#include "cap_helpers.h"
#include <stdio.h>
#include <string.h>

static int wait_for_pid(pid_t pid)
{
	int status, ret;

again:
	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		if (errno == EINTR)
			goto again;

		return -1;
	}

	if (!WIFEXITED(status))
		return -1;

	return WEXITSTATUS(status);
}

/* negative return value -> some internal error
 * positive return value -> userns creation failed
 * 0                     -> userns creation succeeded
 */
static int create_user_ns(void)
{
	pid_t pid;

	pid = fork();
	if (pid < 0)
		return -1;

	if (pid == 0) {
		if (unshare(CLONE_NEWUSER))
			_exit(EXIT_FAILURE);
		_exit(EXIT_SUCCESS);
	}

	return wait_for_pid(pid);
}

static bool bpf_lsm_enabled(void)
{
	FILE *f;
	char buf[512];
	bool enabled = false;

	f = fopen("/sys/kernel/security/lsm", "r");
	if (!f)
		return false;

	if (!fgets(buf, sizeof(buf), f)) {
		fclose(f);
		return false;
	}
	fclose(f);

	buf[strcspn(buf, "\n")] = '\0';

	for (char *saveptr = NULL, *tok = strtok_r(buf, ",", &saveptr);
		tok;
		tok = strtok_r(NULL, ",", &saveptr)) {
		if (!strcmp(tok, "bpf")) {
			enabled = true;
			break;
		}
	}

	return enabled;
}

static void test_userns_create_bpf(void)
{
	__u32 cap_mask = 1ULL << CAP_SYS_ADMIN;
	__u64 old_caps = 0;

	cap_enable_effective(cap_mask, &old_caps);

	ASSERT_OK(create_user_ns(), "priv new user ns");

	cap_disable_effective(cap_mask, &old_caps);

	ASSERT_EQ(create_user_ns(), EPERM, "unpriv new user ns");

	if (cap_mask & old_caps)
		cap_enable_effective(cap_mask, NULL);
}

static void test_unpriv_userns_create_no_bpf(void)
{
	__u32 cap_mask = 1ULL << CAP_SYS_ADMIN;
	__u64 old_caps = 0;

	cap_disable_effective(cap_mask, &old_caps);

	ASSERT_OK(create_user_ns(), "no-bpf unpriv new user ns");

	if (cap_mask & old_caps)
		cap_enable_effective(cap_mask, NULL);
}

void test_deny_namespace(void)
{
	struct test_deny_namespace *skel = NULL;
	int err;

	if (test__start_subtest("unpriv_userns_create_no_bpf"))
		test_unpriv_userns_create_no_bpf();

	skel = test_deny_namespace__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel load"))
		goto close_prog;

	if (!bpf_lsm_enabled()) {
		printf("%s:SKIP:bpf LSM not enabled (boot with lsm=...,bpf)\n",
		       __func__);
		test__skip();
		goto close_prog;
	}

	err = test_deny_namespace__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto close_prog;

	if (test__start_subtest("userns_create_bpf"))
		test_userns_create_bpf();

	test_deny_namespace__detach(skel);

close_prog:
	test_deny_namespace__destroy(skel);
}
