// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <fcntl.h>
#include <unistd.h>

#include "d_path_crash.skel.h"

void test_d_path_crash(void)
{
	struct d_path_crash *skel;

	skel = d_path_crash__open_and_load();
	if (!ASSERT_OK_PTR(skel, "d_path_crash__open_and_load"))
		return;
	skel->bss->pid = getpid();
	ASSERT_OK(d_path_crash__attach(skel), "d_path__attach");
	close(open("/dev/null", O_RDONLY));
	d_path_crash__destroy(skel);
}
