// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../../../include/linux/filter.h"
#include "bpf_misc.h"

/* one page, the program needs two */
struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1);
} arena SEC(".maps");

int runs;

SEC("syscall")
__naked int returns_1(void)
{
	asm volatile (
	".8byte %[adj];"	/* r12 += 32768 */
	"r1 = %[runs] ll;"
	"r0 = 1;"
	"*(u32 *)(r1 + 0) = r0;"
	"exit;"
	:
	: __imm_addr(runs),
	  __imm_insn(adj, BPF_RAW_INSN(BPF_ALU64 | BPF_ADD | BPF_K, 12, 0, 0, 32768))
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
