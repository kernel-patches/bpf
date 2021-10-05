# SPDX-License-Identifier: GPL-2.0-only
# MIPS networking code

obj-$(CONFIG_MIPS_CBPF_JIT) += bpf_jit.o bpf_jit_asm.o

obj-$(CONFIG_MIPS_EBPF_JIT) += ebpf_jit_core.o
ifeq ($(CONFIG_CPU_MIPS64),y)
	obj-$(CONFIG_MIPS_EBPF_JIT) += ebpf_jit_comp64.o
else
	obj-$(CONFIG_MIPS_EBPF_JIT) += ebpf_jit_comp32.o
endif
