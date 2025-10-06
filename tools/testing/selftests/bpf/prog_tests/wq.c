// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Benjamin Tissoires */
#include <test_progs.h>
#include <bpf/btf.h>
#include "wq.skel.h"
#include "wq_failures.skel.h"

static void test_failure_map_no_btf(void);

void serial_test_wq(void)
{
	struct wq *wq_skel = NULL;
	int err, prog_fd;

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	if (test__start_subtest("test_failure_map_no_btf"))
		test_failure_map_no_btf();

	RUN_TESTS(wq);

	/* re-run the success test to check if the timer was actually executed */

	wq_skel = wq__open_and_load();
	if (!ASSERT_OK_PTR(wq_skel, "wq_skel_load"))
		return;

	err = wq__attach(wq_skel);
	if (!ASSERT_OK(err, "wq_attach"))
		return;

	prog_fd = bpf_program__fd(wq_skel->progs.test_syscall_array_sleepable);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	usleep(50); /* 10 usecs should be enough, but give it extra */

	ASSERT_EQ(wq_skel->bss->ok_sleepable, (1 << 1), "ok_sleepable");
	wq__destroy(wq_skel);
}

void serial_test_failures_wq(void)
{
	RUN_TESTS(wq_failures);
}

static void test_failure_map_no_btf(void)
{
	char log[8192];
	struct btf *vmlinux_btf = libbpf_find_kernel_btf();
	int kfunc_id = btf__find_by_name_kind(vmlinux_btf, "bpf_wq_init", BTF_KIND_FUNC);
	int map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "map_no_btf", sizeof(__u32), sizeof(__u64),
				    100, NULL);
	struct bpf_insn prog[] = {
		/* key = 42 on stack at [fp-4] */
		BPF_MOV64_IMM(BPF_REG_0, 42), /* r0 = 42 */
		BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4), /* *(u32 *)(fp-4) = 42 */

		/* r1 = &map (patched from map_fd), r2 = &key */
		BPF_LD_MAP_FD(BPF_REG_1, map_fd), /* r1 = map */
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10), /* r2 = fp */
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), /* r2 = fp-4 (key addr) */

		/* map_val = bpf_map_lookup_elem(map, &key) */
		BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem), /* r0 = map_val or NULL */

		/* if (!map_val) goto out; */
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 4), /* if (r0 == NULL) skip next 4 insns */

		/* wq = (void *)(map_val + 0);  -> use r0 as arg1 directly */
		BPF_MOV64_REG(BPF_REG_1, BPF_REG_0), /* r1 = wq (= val ptr) */

		/* bpf_wq_init(wq, &map, 0) */
		BPF_LD_MAP_FD(BPF_REG_2, map_fd), /* r2 = map */
		BPF_MOV64_IMM(BPF_REG_3, 0), /* r3 = flags (0) */
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_KFUNC_CALL, 0,
			     kfunc_id), /* r0 = bpf_wq_init(wq, &map, 0) */
		BPF_EXIT_INSN(), /* return -3 */
	};
	LIBBPF_OPTS(bpf_prog_load_opts, opts, .log_size = sizeof(log), .log_buf = log,
		    .log_level = 2);
	int r = bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT, NULL, "GPL", prog, ARRAY_SIZE(prog), &opts);

	ASSERT_NEQ(r, 0, "prog load failed");
	ASSERT_HAS_SUBSTR(log, "map 'map_no_btf' has to have BTF in order to use bpf_wq",
			  "log complains no map BTF");
}
