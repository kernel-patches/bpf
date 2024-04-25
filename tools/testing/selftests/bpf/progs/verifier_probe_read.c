#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

SEC("syscall")
__description("probe read 4 bytes")
__success __retval(0)
int probe_read_4(void)
{
	int data = 0x200;
	int data_dst = 0;
	int err;

	err = bpf_probe_read_kernel(&data_dst, 4, &data);
	if (err)
		return err;
	if (data_dst == 0x200)
		return 0;
	return 1;
}

SEC("syscall")
__description("probe read 8 bytes")
__success __retval(0)
int probe_read_8(void)
{
	int data = 0x200;
	int data_dst = 0;
	int err;

	err = bpf_probe_read_kernel(&data_dst, 8, &data);
	if (err)
		return err;

	if (data_dst == 0x200)
		return 0;
	return 1;
}
