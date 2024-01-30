// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Isovalent */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} just_a_map SEC(".maps");

static inline void beef(void)
{
	asm volatile("r8 = 0xbeef" ::: "r8");
}

static inline void cafe(void)
{
	asm volatile("r7 = 0xcafe" ::: "r7");
}

/*
 * Trivial program: every insn maps to the original index
 */
SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int check_trivial_prog(void *ctx)
{
	beef();
	cafe();
	beef();
	cafe();
	beef();

	return 0;
}

/* Some random instructions which will be patched for sure */
static inline void beefify(void)
{
	__u32 key = 0;
	__u64 *x;

	beef();
	bpf_printk("%llx", bpf_jiffies64());
	beef();

	key = !!bpf_jiffies64();
	x = bpf_map_lookup_elem(&just_a_map, &key);
	if (!x)
		return;

	beef();
}

/*
 * Simple program: one section, no bpf-to-bpf calls, some patches
 */
SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int check_simple_prog(void *ctx)
{
	beefify();
	return 0;
}

int __noinline foobar(int x)
{
	beefify();
	return x;
}

/*
 * Same simple program + a bpf-to-bpf call
 */
SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int check_bpf_to_bpf(void *ctx)
{
	beefify();

	return foobar(0);
}

static inline void dead_code1(void)
{
	asm volatile("goto +0");
}

static inline void dead_code100(void)
{
#	if defined(__clang__)
#		pragma clang loop unroll_count(100)
#	elif defined(__GNUC__)
#		pragma GCC unroll 100
#	else
#		error "unroll this loop, please"
#	endif
	for (int i = 0; i < 100; i++)
		asm volatile("goto +0");
}

/*
 * Some beef instructions, patches, plus dead code
 */
static __always_inline void dead_beef(void)
{
	beef();		/* 1 beef */
	dead_code1();
	beef();		/* 1 beef */
	dead_code1();
	beef();		/* 1 beef */
	dead_code100();
	beef();		/* 1 beef */

	dead_code100();
	beefify();	/* 3 beef */
	dead_code100();
	beefify();	/* 3 beef */
	dead_code1();
	beefify();	/* 3 beef */

	/* 13 beef insns total */
}

/*
 * A program with some nops to be removed
 */
SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int check_prog_dead_code(void *ctx)
{
	dead_beef();

	return 0;
}

int __noinline foobar2(int x)
{
	dead_beef();

	return x;
}

/*
 * A program with some nops to be removed + a bpf-to-bpf call to a similar func
 */
SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int check_prog_dead_code_bpf_to_bpf(void *ctx)
{
	dead_beef();

	return foobar2(0);
}

char _license[] SEC("license") = "GPL";
