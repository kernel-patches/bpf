// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

extern int bpf_security_locked_down(enum lockdown_reason what) __ksym;

/* Reason nothing in the test environment genuinely queries or locks. */
#define DENY_REASON LOCKDOWN_HIBERNATION
#define ALLOW_REASON LOCKDOWN_KEXEC

int ret_clear = 1;
int ret_denied = 1;
int ret_invalid_low = 1;
int ret_invalid_high = 1;

SEC("lsm/locked_down")
int BPF_PROG(lockdown_hook, enum lockdown_reason what)
{
	return what == DENY_REASON ? -EPERM : 0;
}

SEC("syscall")
int query(void *ctx)
{
	ret_clear = bpf_security_locked_down(ALLOW_REASON);
	ret_denied = bpf_security_locked_down(DENY_REASON);
	ret_invalid_low = bpf_security_locked_down(LOCKDOWN_NONE);
	ret_invalid_high = bpf_security_locked_down(LOCKDOWN_CONFIDENTIALITY_MAX);
	return 0;
}
