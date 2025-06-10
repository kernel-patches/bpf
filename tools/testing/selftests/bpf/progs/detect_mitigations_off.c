// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_core_read.h>

enum cpu_mitigations {
	CPU_MITIGATIONS_OFF = 0,
};

extern const void cpu_mitigations __ksym __weak;

SEC("syscall")
int cpu_mitigations_off(void *ctx)
{
	__u64 val, off_val;

	if (!&cpu_mitigations)
		return 1;
	off_val = bpf_core_enum_value(enum cpu_mitigations, CPU_MITIGATIONS_OFF);
	bpf_core_read(&val, bpf_core_type_size(enum cpu_mitigations), &cpu_mitigations);
	return val == off_val;
}

char _license[] SEC("license") = "GPL";
