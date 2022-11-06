// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include "timer_crash.skel.h"

enum {
	MODE_ARRAY,
	MODE_HASH,
};

static void test_timer_crash_mode(int mode)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	struct timer_crash *skel;

	skel = timer_crash__open_and_load();
	if (!ASSERT_OK_PTR(skel, "timer_crash__open_and_load"))
		return;
	skel->bss->pid = getpid();
	skel->bss->crash_map = mode;
	if (!ASSERT_OK(timer_crash__attach(skel), "timer_crash__attach"))
		goto end;
	ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.timer), &topts), "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run retval");
end:
	timer_crash__destroy(skel);
}

void test_timer_crash(void)
{
	if (test__start_subtest("array"))
		test_timer_crash_mode(MODE_ARRAY);
	if (test__start_subtest("hash"))
		test_timer_crash_mode(MODE_HASH);
}
