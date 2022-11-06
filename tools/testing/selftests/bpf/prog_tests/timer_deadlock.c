#include <test_progs.h>
#include <network_helpers.h>

#include "timer_deadlock.skel.h"

void test_timer_deadlock(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	struct timer_deadlock *skel;

	/* Remove to observe deadlock */
	test__skip();
	return;

	skel = timer_deadlock__open_and_load();
	if (!ASSERT_OK_PTR(skel, "timer_deadlock__open_and_load"))
		return;
	if (!ASSERT_OK(timer_deadlock__attach(skel), "timer_deadlock__attach"))
		goto end;
	ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.tc_prog), &topts), "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run retval");
end:
	timer_deadlock__destroy(skel);
}

