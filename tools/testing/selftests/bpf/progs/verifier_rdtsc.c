// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Inc. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

SEC("syscall")
__arch_x86_64
__xlated("0: call kernel-function")
__naked int bpf_rdtsc(void)
{
	asm volatile(
	"call %[bpf_get_hw_counter];"
	"exit"
	:
	: __imm(bpf_get_hw_counter)
	: __clobber_all
	);
}

SEC("syscall")
__arch_x86_64
/* program entry for bpf_rdtsc_jit_x86_64(), regular function prologue */
__jited("	endbr64")
__jited("	nopl	(%rax,%rax)")
__jited("	nopl	(%rax)")
__jited("	pushq	%rbp")
__jited("	movq	%rsp, %rbp")
__jited("	endbr64")
/* save RDX in R11 as it will be overwritten */
__jited("	movq	%rdx, %r11")
/* lfence may not be executed depending on cpu features */
__jited("	{{(lfence|)}}")
__jited("	rdtsc")
/* combine EDX:EAX into RAX */
__jited("	shlq	${{(32|0x20)}}, %rdx")
__jited("	orq	%rdx, %rax")
/* restore RDX from R11 */
__jited("	movq	%r11, %rdx")
__jited("	leave")
__naked int bpf_rdtsc_jit_x86_64(void)
{
	asm volatile(
	"call %[bpf_get_hw_counter];"
	"exit"
	:
	: __imm(bpf_get_hw_counter)
	: __clobber_all
	);
}

void rdtsc(void)
{
	bpf_get_hw_counter();
}

char _license[] SEC("license") = "GPL";
