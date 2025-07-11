#include "vmlinux.h"
#include <limits.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

__u64 sig_verify_retval = -INT_MAX;

SEC("fexit/bpf_prog_verify_signature")
int BPF_PROG(bpf_sign, struct bpf_prog *prog, union bpf_attr *attr, bool is_kernel, int ret)
{
	sig_verify_retval = ret;
	return 0;
}
