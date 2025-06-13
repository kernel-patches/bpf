// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

struct bpf_testmod_struct_arg_4 {
	u64 a;
	int b;
};


SEC("fentry/bpf_testmod_test_struct_arg_7")
int BPF_PROG2(test_struct_many_args_1, __u64, a, void *, b, short, c, int, d,
	      void *, e, struct bpf_testmod_struct_arg_4, f)
{
	return 0;
}

SEC("fexit/bpf_testmod_test_struct_arg_7")
int BPF_PROG2(test_struct_many_args_2, __u64, a, void *, b, short, c, int, d,
	      void *, e, struct bpf_testmod_struct_arg_4, f, int, ret)
{
	return 0;
}
char _license[] SEC("license") = "GPL";
