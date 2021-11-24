// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "multi_uprobe.skel.h"

/* this is how USDT semaphore is actually defined, except volatile modifier */
extern volatile unsigned short uprobe_ref_ctr;

/* attach points */
static void method0(void) { return ; }
static void method1(void) { return ; }
static void method2(void) { return ; }
static void method3(void) { return ; }
static void method4(void) { return ; }
static void method5(void) { return ; }
static void method6(void) { return ; }
static void method7(void) { return ; }

void test_multi_uprobe_test(void)
{
	DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
	struct bpf_link *uretprobe_link = NULL;
	struct bpf_link *uprobe_link = NULL;
	ssize_t base_addr, ref_ctr_offset;
	struct multi_uprobe *skel;
	const char *paths[8];
	int duration = 0;
	__u64 offs[8];

	skel = multi_uprobe__open_and_load();
	if (CHECK(!skel, "skel_open", "failed to open skeleton\n"))
		return;

	base_addr = get_base_addr();
	if (CHECK(base_addr < 0, "get_base_addr",
		  "failed to find base addr: %zd", base_addr))
		return;

	ref_ctr_offset = get_rel_offset((uintptr_t)&uprobe_ref_ctr);
	if (!ASSERT_GE(ref_ctr_offset, 0, "ref_ctr_offset"))
		return;

#define INIT(__i)								\
	do {									\
		paths[__i] = (const char *) "/proc/self/exe";			\
		offs[__i]  = get_uprobe_offset(&method ## __i, base_addr);	\
	} while (0)

	INIT(0);
	INIT(1);
	INIT(2);
	INIT(3);
	INIT(4);
	INIT(5);
	INIT(6);
	INIT(7);

#undef INIT

	uprobe_opts.multi.paths = paths;
	uprobe_opts.multi.offs = offs;

	uprobe_opts.multi.cnt = 8;

	uprobe_opts.retprobe = false;
	uprobe_opts.ref_ctr_offset = ref_ctr_offset;
	uprobe_link = bpf_program__attach_uprobe_opts(skel->progs.handle_uprobe,
						      0 /* self pid */,
						      NULL, 0,
						      &uprobe_opts);
	if (!ASSERT_OK_PTR(uprobe_link, "attach_uprobe"))
		goto cleanup;

	uprobe_opts.retprobe = true;
	uretprobe_link = bpf_program__attach_uprobe_opts(skel->progs.handle_uretprobe,
							 -1 /* any pid */,
							 NULL, 0,
							 &uprobe_opts);
	if (!ASSERT_OK_PTR(uretprobe_link, "attach_uretprobe"))
		goto cleanup;

	method0();
	method1();
	method2();
	method3();
	method4();
	method5();
	method6();
	method7();

	ASSERT_EQ(skel->bss->test_uprobe_result, 8, "test_uprobe_result");
	ASSERT_EQ(skel->bss->test_uretprobe_result, 8, "test_uretprobe_result");

cleanup:
	bpf_link__destroy(uretprobe_link);
	bpf_link__destroy(uprobe_link);
	multi_uprobe__destroy(skel);
}
