// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

/* Inputs, set from userspace before each run. */
u64 set_cgid;
long set_mode;
u64 get_cgid;

/* Results, read back after each run. */
long set_ret;
long get_mode;

extern int bpf_numab_set_mode(u64 cgid, enum numab_mode mode) __ksym;
extern s64 bpf_numab_get_mode(u64 cgid) __ksym;

SEC("syscall")
int numab_set(void *ctx)
{
	set_ret = bpf_numab_set_mode(set_cgid, (enum numab_mode)set_mode);
	return 0;
}

SEC("syscall")
int numab_get(void *ctx)
{
	get_mode = bpf_numab_get_mode(get_cgid);
	return 0;
}

char _license[] SEC("license") = "GPL";
