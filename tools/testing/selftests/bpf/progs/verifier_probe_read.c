#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

SEC("syscall")
__description("probe read 4 bytes")
__success __retval(0x200)
u64 probe_read_4(void)
{
	u32 data = 0x200;
	u64 data_dst;
	int err;

	err = bpf_probe_read_kernel(&data_dst, 4, &data);
	if (err)
		return 0;
	return data_dst;
}

SEC("syscall")
__description("probe read 8 bytes")
__success __retval(0x200)
u64 probe_read_8(void)
{
	u32 data = 0x200;
	u64 data_dst;
	int err;

	err = bpf_probe_read_kernel(&data_dst, 8, &data);
	if (err)
		return 0;
	return data_dst;
}
