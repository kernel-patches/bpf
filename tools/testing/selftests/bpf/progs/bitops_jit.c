// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"
#include "bpf_misc.h"

SEC("syscall")
__description("bitops jit: clz64 uses lzcnt on x86 with abm")
__success __retval(63)
__arch_x86_64
__cpu_feature("abm")
__jited("	lzcnt{{.*}}")
int bitops_jit_clz64_x86(void *ctx)
{
	return bpf_clz64(1);
}

SEC("syscall")
__description("bitops jit: ctz64 uses tzcnt on x86 with bmi1")
__success __retval(4)
__arch_x86_64
__cpu_feature("bmi1")
__jited("	tzcnt{{.*}}")
int bitops_jit_ctz64_x86(void *ctx)
{
	return bpf_ctz64(0x10);
}

SEC("syscall")
__description("bitops jit: ffs64 uses tzcnt on x86 with bmi1")
__success __retval(5)
__arch_x86_64
__cpu_feature("bmi1")
__jited("	tzcnt{{.*}}")
int bitops_jit_ffs64_x86(void *ctx)
{
	return bpf_ffs64(0x10);
}

SEC("syscall")
__description("bitops jit: fls64 uses lzcnt on x86 with abm")
__success __retval(5)
__arch_x86_64
__cpu_feature("abm")
__jited("	lzcnt{{.*}}")
int bitops_jit_fls64_x86(void *ctx)
{
	return bpf_fls64(0x10);
}

SEC("syscall")
__description("bitops jit: popcnt64 uses popcnt on x86")
__success __retval(3)
__arch_x86_64
__cpu_feature("popcnt")
__jited("	popcnt{{.*}}")
int bitops_jit_popcnt64_x86(void *ctx)
{
	return bpf_popcnt64(0x1011);
}

SEC("syscall")
__description("bitops jit: rol64 uses rol on x86")
__success __retval(6)
__arch_x86_64
__jited("	rol{{.*}}")
int bitops_jit_rol64_x86(void *ctx)
{
	return bpf_rol64(3, 1);
}

SEC("syscall")
__description("bitops jit: ror64 uses ror on x86")
__success __retval(3)
__arch_x86_64
__jited("	ror{{.*}}")
int bitops_jit_ror64_x86(void *ctx)
{
	return bpf_ror64(6, 1);
}

SEC("syscall")
__description("bitops jit: clz64 uses clz on arm64")
__success __retval(63)
__arch_arm64
__jited("	clz	{{.*}}")
int bitops_jit_clz64_arm64(void *ctx)
{
	return bpf_clz64(1);
}

SEC("syscall")
__description("bitops jit: ctz64 uses ctz or rbit+clz on arm64")
__success __retval(4)
__arch_arm64
__jited("	{{(ctz|rbit)}}	{{.*}}")
int bitops_jit_ctz64_arm64(void *ctx)
{
	return bpf_ctz64(0x10);
}

SEC("syscall")
__description("bitops jit: ffs64 uses ctz or rbit+clz on arm64")
__success __retval(5)
__arch_arm64
__jited("	{{(ctz|rbit)}}	{{.*}}")
int bitops_jit_ffs64_arm64(void *ctx)
{
	return bpf_ffs64(0x10);
}

SEC("syscall")
__description("bitops jit: fls64 uses clz on arm64")
__success __retval(5)
__arch_arm64
__jited("	clz	{{.*}}")
int bitops_jit_fls64_arm64(void *ctx)
{
	return bpf_fls64(0x10);
}

SEC("syscall")
__description("bitops jit: bitrev64 uses rbit on arm64")
__success __retval(1)
__arch_arm64
__jited("	rbit	{{.*}}")
int bitops_jit_bitrev64_arm64(void *ctx)
{
	return bpf_bitrev64(0x8000000000000000ULL);
}

SEC("syscall")
__description("bitops jit: rol64 uses rorv on arm64")
__success __retval(6)
__arch_arm64
__jited("	ror	{{.*}}")
int bitops_jit_rol64_arm64(void *ctx)
{
	return bpf_rol64(3, 1);
}

SEC("syscall")
__description("bitops jit: ror64 uses rorv on arm64")
__success __retval(3)
__arch_arm64
__jited("	ror	{{.*}}")
int bitops_jit_ror64_arm64(void *ctx)
{
	return bpf_ror64(6, 1);
}

char _license[] SEC("license") = "GPL";
