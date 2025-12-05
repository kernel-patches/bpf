// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>

#include "cgroup_helpers.h"

#define FOO		"/foo"
#define BAR		"/foo/bar/"
#define PING_CMD	"ping -q -c1 -w1 127.0.0.1 > /dev/null"

static char bpf_log_buf[BPF_LOG_BUF_SIZE];

static int prog_load(int verdict)
{
	struct bpf_insn prog[] = {
		BPF_MOV64_IMM(BPF_REG_0, verdict), /* r0 = verdict */
		BPF_EXIT_INSN(),
	};
	size_t insns_cnt = ARRAY_SIZE(prog);

	return bpf_test_load_program(BPF_PROG_TYPE_CGROUP_SKB,
			       prog, insns_cnt, "GPL", 0,
			       bpf_log_buf, BPF_LOG_BUF_SIZE);
}

void serial_test_cgroup_attach_override(void)
{
	int drop_prog = -1, allow_prog = -1, foo = -1, bar = -1;

	allow_prog = prog_load(1);
	if (!ASSERT_OK_FD(allow_prog, "prog_load_allow")) {
		printf("verifier output:\n%s\n-------\n", bpf_log_buf);
		goto err;
	}

	drop_prog = prog_load(0);
	if (!ASSERT_OK_FD(drop_prog, "prog_load_drop")) {
		printf("verifier output:\n%s\n-------\n", bpf_log_buf);
		goto err;
	}

	foo = test__join_cgroup(FOO);
	if (!ASSERT_OK_FD(foo, "cgroup_join_foo"))
		goto err;

	if (!ASSERT_OK(bpf_prog_attach(drop_prog, foo, BPF_CGROUP_INET_EGRESS,
				       BPF_F_ALLOW_OVERRIDE),
		       "prog_attach_drop_foo_override"))
		goto err;

	if (!ASSERT_NEQ(system(PING_CMD), 0, "ping expcted to fail"))
		goto err;

	bar = test__join_cgroup(BAR);
	if (!ASSERT_OK_FD(bar, "cgroup_join_bar"))
		goto err;

	if (!ASSERT_NEQ(system(PING_CMD), 0, "ping expected to fail"))
		goto err;

	if (!ASSERT_OK(bpf_prog_attach(allow_prog, bar, BPF_CGROUP_INET_EGRESS,
				       BPF_F_ALLOW_OVERRIDE),
		       "prog_attach_allow_bar_override"))
		goto err;

	if (!ASSERT_OK(system(PING_CMD), "ping_ok"))
		goto err;

	if (!ASSERT_OK(bpf_prog_detach(bar, BPF_CGROUP_INET_EGRESS),
		       "prog_detach_bar"))
		goto err;

	if (!ASSERT_NEQ(system(PING_CMD), 0, "ping expcted to fail"))
		goto err;

	if (!ASSERT_OK(bpf_prog_attach(allow_prog, bar, BPF_CGROUP_INET_EGRESS,
				       BPF_F_ALLOW_OVERRIDE),
		       "prog_attach_allow_bar_override"))
		goto err;

	if (!ASSERT_OK(bpf_prog_detach(foo, BPF_CGROUP_INET_EGRESS),
		       "prog_detach_foo"))
		goto err;

	if (!ASSERT_OK(system(PING_CMD), "ping_ok"))
		goto err;

	if (!ASSERT_OK(bpf_prog_attach(allow_prog, bar, BPF_CGROUP_INET_EGRESS,
				       BPF_F_ALLOW_OVERRIDE),
		       "prog_attach_allow_bar_override"))
		goto err;

	if (!ASSERT_ERR(bpf_prog_attach(allow_prog, bar, BPF_CGROUP_INET_EGRESS, 0),
			"fail_prog_attach_allow_bar_none"))
		goto err;

	if (!ASSERT_OK(bpf_prog_detach(bar, BPF_CGROUP_INET_EGRESS),
		       "prog_detach_bar"))
		goto err;

	if (!ASSERT_ERR(bpf_prog_detach(foo, BPF_CGROUP_INET_EGRESS),
			"fail_prog_detach_foo"))
		goto err;

	if (!ASSERT_OK(bpf_prog_attach(allow_prog, foo, BPF_CGROUP_INET_EGRESS, 0),
		       "prog_attach_allow_foo_none"))
		goto err;

	if (!ASSERT_ERR(bpf_prog_attach(allow_prog, bar, BPF_CGROUP_INET_EGRESS, 0),
			"fail_prog_attach_allow_bar_none"))
		goto err;

	if (!ASSERT_ERR(bpf_prog_attach(allow_prog, bar, BPF_CGROUP_INET_EGRESS,
					BPF_F_ALLOW_OVERRIDE),
			"fail_prog_attach_allow_bar_override"))
		goto err;

	if (!ASSERT_ERR(bpf_prog_attach(allow_prog, foo, BPF_CGROUP_INET_EGRESS,
					BPF_F_ALLOW_OVERRIDE),
			"fail_prog_attach_allow_foo_override"))
		goto err;

	if (!ASSERT_OK(bpf_prog_attach(drop_prog, foo, BPF_CGROUP_INET_EGRESS, 0),
		       "prog_attach_drop_foo_none"))
		goto err;

err:
	close(foo);
	close(bar);
	close(allow_prog);
	close(drop_prog);
}
