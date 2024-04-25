#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

SEC("syscall")
__description("probe read 4 bytes")
__success __retval(0x200)
long probe_read_4(void)
{
	int garbage1 = 0x1;
	int data = 0x200;
	int garbage2 = 0x2;
	long data_dst = 0;
	int err;

	err = bpf_probe_read_kernel(&data_dst, 4, &data);
	if (err)
		return garbage1 + garbage2; /* avoid unused variable */
	return data_dst;
}

SEC("syscall")
__description("probe read 8 bytes")
__success __retval(0x200)
long probe_read_8(void)
{
	int garbage1 = 0x1;
	int data = 0x200;
	int garbage2 = 0x2;
	long data_dst = 0;
	int err;

	err = bpf_probe_read_kernel(&data_dst, 8, &data);
	if (err)
		return garbage1 + garbage2;
	return data_dst;
}
