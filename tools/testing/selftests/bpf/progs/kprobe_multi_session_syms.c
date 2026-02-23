// SPDX-License-Identifier: GPL-2.0
/* Test kprobe.session with exact function names to verify syms[] optimization */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>

char _license[] SEC("license") = "GPL";

int pid = 0;

/* Results for each function: incremented on entry and return */
__u64 test1_count = 0;

/* Track entry vs return */
bool test1_return = false;

/*
 * No tests in here, just to trigger 'bpf_fentry_test*'
 * through tracing test_run
 */
SEC("fentry/bpf_modify_return_test")
int BPF_PROG(trigger)
{
	return 0;
}

/*
 * Test 1: Exact function name (no wildcards) - uses fast syms[] path
 * This should attach via opts.syms array, bypassing kallsyms parsing
 */
SEC("kprobe.session/bpf_fentry_test1")
int test_kprobe_syms_1(struct pt_regs *ctx)
{
	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	test1_count++;

	/* Check if this is return probe */
	if (bpf_session_is_return(ctx))
		test1_return = true;

	return 0;  /* Always execute return probe */
}
