// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "unwound.skel.h"

/* Run the prog once. What it returns, what bpf_prog_info says and what is in its stderr. */
static void run(struct bpf_program *prog, int retval, bool unwound, const char *msg)
{
	char pkt[64] = {}, buf[4096] = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = pkt, .data_size_in = sizeof(pkt), .repeat = 1);
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);
	int fd = bpf_program__fd(prog);

	if (!test__start_subtest(bpf_program__name(prog)))
		return;

	ASSERT_OK(bpf_prog_get_info_by_fd(fd, &info, &len), "info_before");
	ASSERT_EQ((int)info.unwound, 0, "unwound_before");

	ASSERT_OK(bpf_prog_test_run_opts(fd, &opts), "test_run");
	ASSERT_EQ(opts.retval, retval, "retval");

	memset(&info, 0, sizeof(info));
	len = sizeof(info);
	ASSERT_OK(bpf_prog_get_info_by_fd(fd, &info, &len), "info_after");
	ASSERT_EQ((int)info.unwound, (int)unwound, "unwound_after");

	bpf_prog_stream_read(fd, BPF_STREAM_STDERR, buf, sizeof(buf) - 1, NULL);
	if (msg)
		ASSERT_HAS_SUBSTR(buf, msg, "stderr");
	else
		ASSERT_STREQ(buf, "", "stderr");
}

/*
 * The trampoline of fexit calls the target and stays on the stack at every level of a recursion.
 * The check of the stack in the target knows nothing about it.
 */
static void attach(struct unwound *tgt, const char *name, const char *msg)
{
	static char log_buf[4096];
	struct bpf_program *prog, *p;
	struct unwound *skel;
	int err;

	if (!test__start_subtest(name))
		return;
	skel = unwound__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;
	prog = bpf_object__find_program_by_name(skel->obj, name);
	if (!ASSERT_OK_PTR(prog, name))
		goto out;
	bpf_object__for_each_program(p, skel->obj)
		bpf_program__set_autoload(p, p == prog);
	log_buf[0] = 0;
	bpf_program__set_log_buf(prog, log_buf, sizeof(log_buf));
	err = bpf_program__set_attach_target(prog, bpf_program__fd(tgt->progs.too_deep),
					     "calls_itself");
	if (!ASSERT_OK(err, "set_attach_target"))
		goto out;
	err = unwound__load(skel);
	if (msg) {
		ASSERT_ERR(err, name);
		ASSERT_HAS_SUBSTR(log_buf, msg, name);
	} else {
		ASSERT_OK(err, name);
	}
out:
	unwound__destroy(skel);
}

void test_unwound(void)
{
	struct unwound *skel;

#if !defined(__x86_64__) && !defined(__aarch64__)
	/* unwinding, per-cpu insns and timed may_goto in JIT */
	test__skip();
	return;
#endif
	skel = unwound__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	run(skel->progs.caught, 42, false, NULL);
	run(skel->progs.not_caught, 7, true, "ERROR: The program was unwound");
	run(skel->progs.spins, 0, true, "ERROR: Timeout detected for may_goto instruction");
	run(skel->progs.too_deep, 3, true,
	    "ERROR: No room in the stack for a call of a recursive function");

	attach(skel, "on_entry", NULL);
	attach(skel, "on_exit", "Only fentry can attach to calls_itself, which is recursive");

	unwound__destroy(skel);
}
