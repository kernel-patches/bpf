// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

extern int bpf_security_locked_down(enum lockdown_reason what) __ksym;

/* Tracing programs must be rejected by the kfunc filter. */
SEC("fentry/bpf_fentry_test1")
__failure __msg("calling kernel function bpf_security_locked_down is not allowed")
int BPF_PROG(tracing_caller, int a)
{
	bpf_security_locked_down(LOCKDOWN_KEXEC);
	return 0;
}

/* As must locked_down programs, which would recurse into the dispatch. */
SEC("lsm/locked_down")
__failure __msg("calling kernel function bpf_security_locked_down is not allowed")
int BPF_PROG(recursive_caller, enum lockdown_reason what)
{
	return bpf_security_locked_down(what);
}
