// SPDX-License-Identifier: GPL-2.0
#include <sys/timerfd.h>
#include <unistd.h>

#include <test_progs.h>
#include "task_storage_hrtimer.skel.h"

#define TRIGGER_COUNT 1000

void test_task_storage_hrtimer(void)
{
	struct itimerspec timer = {
		.it_value.tv_nsec = 1000000,
	};
	struct task_storage_hrtimer *skel;
	int err, fd = -1, i;

	skel = task_storage_hrtimer__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	skel->bss->target_tgid = getpid();
	err = task_storage_hrtimer__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto cleanup;

	fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
	if (!ASSERT_GE(fd, 0, "timerfd_create"))
		goto cleanup;

	for (i = 0; i < TRIGGER_COUNT; i++) {
		err = timerfd_settime(fd, 0, &timer, NULL);
		if (!ASSERT_OK(err, "timerfd_settime"))
			goto cleanup;
	}

	task_storage_hrtimer__detach(skel);

	ASSERT_GE(skel->bss->seen, TRIGGER_COUNT, "seen");
	ASSERT_EQ(skel->bss->attempted, skel->bss->seen, "attempted");
	ASSERT_GT(skel->bss->succeeded, 0, "succeeded");
	ASSERT_EQ(skel->bss->delete_errors, 0, "delete_errors");
	ASSERT_EQ(skel->bss->attempted,
		  skel->bss->succeeded + skel->bss->failed, "attempts");

cleanup:
	if (fd >= 0)
		close(fd);
	task_storage_hrtimer__destroy(skel);
}
