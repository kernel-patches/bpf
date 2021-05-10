// SPDX-License-Identifier: GPL-2.0
#include <uapi/linux/seccomp.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/unistd.h>
#include <uapi/linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <uapi/linux/audit.h>

#if defined(__x86_64__)
#define ARCH	AUDIT_ARCH_X86_64
#elif defined(__i386__)
#define ARCH	AUDIT_ARCH_I386
#else
#endif

#ifdef ARCH
/* Returns EPERM when trying to close fd 999 */
SEC("seccomp")
int bpf_prog1(struct seccomp_data *ctx)
{
	/*
	 * Make sure this BPF program is being run on the same architecture it
	 * was compiled on.
	 */
	if (ctx->arch != ARCH)
		return SECCOMP_RET_ERRNO | EPERM;
	if (ctx->nr == __NR_close && ctx->args[0] == 999)
		return SECCOMP_RET_ERRNO | EPERM;

	return SECCOMP_RET_ALLOW;
}
#else
#warning Architecture not supported -- Blocking all syscalls
SEC("seccomp")
int bpf_prog1(struct seccomp_data *ctx)
{
	return SECCOMP_RET_ERRNO | EPERM;
}
#endif

char _license[] SEC("license") = "GPL";
