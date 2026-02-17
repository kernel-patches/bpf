#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

extern u8 *bpf_kfunc_kasan_uaf(void) __ksym;
extern u8 *bpf_kfunc_kasan_oob(void) __ksym;

int kasan_counter;

SEC("tcx/ingress")
int bpf_kasan_uaf(struct __sk_buff *skb)
{
	volatile u8 *result = bpf_kfunc_kasan_uaf();

	return result[0] ? 1 : 0;


}

SEC("tcx/ingress")
int bpf_kasan_oob(struct __sk_buff *skb)
{
	volatile u8 *result = bpf_kfunc_kasan_oob();

	return result[0] ? 1 : 0;
}

char LICENSE[] SEC("license") = "GPL";
