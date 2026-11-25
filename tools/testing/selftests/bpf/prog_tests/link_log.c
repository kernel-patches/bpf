// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>

static const struct link_log_case {
	const char *name;
	enum bpf_prog_type type;
	enum bpf_attach_type attach_type;
	const char *func;
	struct bpf_link_create_opts opts;
	int err;
	const char *msg;
} tests[] = {
	{ "tracing", BPF_PROG_TYPE_TRACING, BPF_TRACE_FENTRY, "bpf_fentry_test1",
	  { .target_btf_id = 1 }, -EINVAL, "target_btf_id" },
#ifdef __x86_64__
	{ "tracing_multi", BPF_PROG_TYPE_TRACING, BPF_TRACE_FENTRY_MULTI, NULL,
	  { .tracing_multi = { .ids = (const __u32[]){ ~0U }, .cnt = 1 } },
	  -EINVAL, "4294967295" },
#endif
	{ "iter", BPF_PROG_TYPE_TRACING, BPF_TRACE_ITER, "bpf_map",
	  { .iter.len = sizeof(union bpf_iter_link_info) }, -EINVAL, "iter_info_len" },
	{ "cgroup", BPF_PROG_TYPE_CGROUP_SKB, BPF_CGROUP_INET_EGRESS, NULL,
	  { .cgroup.expected_revision = 2 }, -ESTALE, "revision" },
};

static void run_test(const struct link_log_case *test)
{
	const struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	struct bpf_link_create_opts opts = test->opts;
	int prog_fd, fd, btf_id, cg = -1;
	LIBBPF_OPTS(bpf_prog_load_opts, load_opts,
		    .expected_attach_type = test->attach_type,
	);
	char buf[128] = {};
	LIBBPF_OPTS(bpf_log_opts, log_opts,
		    .buf = buf,
		    .size = sizeof(buf),
		    .level = 1,
	);

	if (test->func) {
		btf_id = libbpf_find_vmlinux_btf_id(test->func, test->attach_type);
		if (!ASSERT_GT(btf_id, 0, "attach_btf_id"))
			return;

		load_opts.attach_btf_id = btf_id;
	}

	prog_fd = bpf_prog_load(test->type, NULL, "GPL", insns, ARRAY_SIZE(insns), &load_opts);
	if (!ASSERT_OK_FD(prog_fd, "bpf_prog_load"))
		return;

	if (test->type == BPF_PROG_TYPE_CGROUP_SKB) {
		cg = test__join_cgroup("/link_log");
		if (!ASSERT_OK_FD(cg, "join_cgroup"))
			goto out;
	}

	opts.sz = sizeof(opts);
	opts.log_opts = &log_opts;
	fd = bpf_link_create(prog_fd, cg < 0 ? 0 : cg, test->attach_type, &opts);
	if (fd >= 0)
		close(fd);

	ASSERT_EQ(fd, test->err, "err");
	ASSERT_HAS_SUBSTR(buf, test->msg, "log");
	ASSERT_EQ(log_opts.true_size, strlen(buf) + 1, "true_size");

	if (cg >= 0)
		close(cg);
out:
	close(prog_fd);
}

void test_link_log(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(tests); i++)
		if (test__start_subtest(tests[i].name))
			run_test(&tests[i]);
}
