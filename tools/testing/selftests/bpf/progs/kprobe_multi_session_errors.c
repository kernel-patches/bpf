// SPDX-License-Identifier: GPL-2.0
/* Test error code consistency between fast and slow paths for non-existent functions */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

/*
 * Test 1: Non-existent wildcard pattern (slow path)
 * This uses pattern matching with kallsyms parsing and should fail with ENOENT
 */
SEC("kprobe.session/__impossible_test_func_xyz_wildcard_*")
int test_nonexistent_wildcard(struct pt_regs *ctx)
{
	return 0;
}

/*
 * Test 2: Non-existent exact function name (fast path)
 * This uses syms[] array and should fail with ENOENT (normalized from ESRCH)
 */
SEC("kprobe.session/__impossible_test_func_xyz_exact_123")
int test_nonexistent_exact(struct pt_regs *ctx)
{
	return 0;
}
