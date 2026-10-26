// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include "may_goto_budget.skel.h"

void test_may_goto_budget(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	struct may_goto_budget *skel;
	int i;

	skel = may_goto_budget__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.timer_after_timeout), &opts),
		  "test_run");
	ASSERT_EQ(opts.retval, 0, "retval");
	ASSERT_GT(skel->bss->spun, 1, "spun");

	for (i = 0; i < 100 && !skel->bss->cb_done; i++)
		usleep(10000);
	ASSERT_EQ(skel->bss->cb_done, 1, "cb_done");
	ASSERT_EQ(skel->bss->cb_cnt, 1000, "cb_cnt");

	may_goto_budget__destroy(skel);
}
