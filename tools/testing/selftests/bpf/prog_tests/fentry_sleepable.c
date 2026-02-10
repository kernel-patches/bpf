// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <unistd.h>
#include "fentry_sleepable.skel.h"

void test_fentry_sleepable(void)
{
	struct fentry_sleepable *skel;
	int buf = 1234;
	int err;

	skel = fentry_sleepable__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_sleepable__open_and_load"))
		return;

	err = fentry_sleepable__attach(skel);
	if (!ASSERT_OK(err, "fentry_sleepable__attach"))
		goto cleanup;

	syscall(__NR_setdomainname, &buf, -2L);
	syscall(__NR_setdomainname, 0, -3L);
	syscall(__NR_setdomainname, ~0L, -4L);

	ASSERT_EQ(skel->bss->copy_test, 3, "copy_test");

cleanup:
	fentry_sleepable__destroy(skel);
}
