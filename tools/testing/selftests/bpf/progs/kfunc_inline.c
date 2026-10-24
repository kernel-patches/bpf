// SPDX-License-Identifier: GPL-2.0

#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

extern __u64 bpf_rol64(__u64 x, __u32 n) __ksym;
extern __u64 bpf_select64(__u64 cond, __u64 a, __u64 b) __ksym;

__u64 in_x, in_y, in_n, in_c;
__u64 out_rol, out_sel, out_lt, out_mix, out_div;

SEC("syscall")
int kfunc_inline(void *ctx)
{
	out_rol = bpf_rol64(in_x, in_n);
	out_sel = bpf_select64(in_c, in_x, in_y);
	out_lt = bpf_kfunc_call_test_fastcall_lt(in_x, in_y);
	out_mix = bpf_kfunc_call_test_fastcall_mix(in_x);
	out_div = bpf_kfunc_call_test_fastcall_div(in_x, in_y);
	return 0;
}

char _license[] SEC("license") = "GPL";
