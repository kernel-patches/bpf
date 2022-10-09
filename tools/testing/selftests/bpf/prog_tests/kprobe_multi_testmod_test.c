// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "kprobe_multi.skel.h"
#include "trace_helpers.h"
#include "bpf/libbpf_internal.h"

static void kprobe_multi_testmod_check(struct kprobe_multi *skel)
{
	ASSERT_EQ(skel->bss->kprobe_testmod_test1_result, 1, "kprobe_test1_result");
	ASSERT_EQ(skel->bss->kprobe_testmod_test2_result, 1, "kprobe_test2_result");
	ASSERT_EQ(skel->bss->kprobe_testmod_test3_result, 1, "kprobe_test3_result");

	ASSERT_EQ(skel->bss->kretprobe_testmod_test1_result, 1, "kretprobe_test1_result");
	ASSERT_EQ(skel->bss->kretprobe_testmod_test2_result, 1, "kretprobe_test2_result");
	ASSERT_EQ(skel->bss->kretprobe_testmod_test3_result, 1, "kretprobe_test3_result");
}

static void test_testmod_link_api(struct bpf_link_create_opts *opts)
{
	int prog_fd, link1_fd = -1, link2_fd = -1;
	struct kprobe_multi *skel = NULL;

	skel = kprobe_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_raw_skel_load"))
		goto cleanup;

	skel->bss->pid = getpid();
	prog_fd = bpf_program__fd(skel->progs.test_kprobe_testmod);
	link1_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_KPROBE_MULTI, opts);
	if (!ASSERT_GE(link1_fd, 0, "link_fd1"))
		goto cleanup;

	opts->kprobe_multi.flags = BPF_F_KPROBE_MULTI_RETURN;
	prog_fd = bpf_program__fd(skel->progs.test_kretprobe_testmod);
	link2_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_KPROBE_MULTI, opts);
	if (!ASSERT_GE(link2_fd, 0, "link_fd2"))
		goto cleanup;

	ASSERT_OK(trigger_module_test_read(1), "trigger_read");
	kprobe_multi_testmod_check(skel);

cleanup:
	if (link1_fd != -1)
		close(link1_fd);
	if (link2_fd != -1)
		close(link2_fd);
	kprobe_multi__destroy(skel);
}

#define GET_ADDR(__sym, __addr) ({					\
	__addr = ksym_get_addr(__sym);					\
	if (!ASSERT_NEQ(__addr, 0, "kallsyms load failed for " #__sym))	\
		return;							\
})

static void test_testmod_link_api_addrs(void)
{
	LIBBPF_OPTS(bpf_link_create_opts, opts);
	unsigned long long addrs[3];

	GET_ADDR("bpf_testmod_fentry_test1", addrs[0]);
	GET_ADDR("bpf_testmod_fentry_test2", addrs[1]);
	GET_ADDR("bpf_testmod_fentry_test3", addrs[2]);

	opts.kprobe_multi.addrs = (const unsigned long *) addrs;
	opts.kprobe_multi.cnt = ARRAY_SIZE(addrs);

	test_testmod_link_api(&opts);
}

static void test_testmod_link_api_syms(void)
{
	LIBBPF_OPTS(bpf_link_create_opts, opts);
	const char *syms[3] = {
		"bpf_testmod_fentry_test1",
		"bpf_testmod_fentry_test2",
		"bpf_testmod_fentry_test3",
	};

	opts.kprobe_multi.syms = syms;
	opts.kprobe_multi.cnt = ARRAY_SIZE(syms);
	test_testmod_link_api(&opts);
}

void serial_test_kprobe_multi_testmod_test(void)
{
	if (!ASSERT_OK(load_kallsyms_refresh(), "load_kallsyms_refresh"))
		return;

	if (test__start_subtest("testmod_link_api_syms"))
		test_testmod_link_api_syms();
	if (test__start_subtest("testmod_link_api_addrs"))
		test_testmod_link_api_addrs();
}
