#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

extern void bpf_local_irq_save(unsigned long *) __ksym __bpf_fastcall;
extern void bpf_local_irq_restore(unsigned long *) __ksym __bpf_fastcall;

__u64 saved_regs[10];

void __kfunc_btf_root(void)
{
	asm volatile ("" : : "r"(&bpf_local_irq_save), "r"(&bpf_local_irq_restore));
}

#define IRQ_SET_REGS \
	"r0 = r7; r0 += 17; r2 = r7; r2 += 34;" \
	"r3 = r7; r3 += 51; r4 = r7; r4 += 68; r5 = r7; r5 += 85;"
#define IRQ_SPILLS \
	"*(u64 *)(r10 - 16) = r0;" \
	"*(u64 *)(r10 - 24) = r2;" \
	"*(u64 *)(r10 - 32) = r3;" \
	"*(u64 *)(r10 - 40) = r4;" \
	"*(u64 *)(r10 - 48) = r5;"
#define IRQ_FILLS \
	"r5 = *(u64 *)(r10 - 48);" \
	"r4 = *(u64 *)(r10 - 40);" \
	"r3 = *(u64 *)(r10 - 32);" \
	"r2 = *(u64 *)(r10 - 24);" \
	"r0 = *(u64 *)(r10 - 16);"
#define IRQ_CAPTURE_REGS \
	"*(u64 *)(r6 + 0) = r0;" \
	"*(u64 *)(r6 + 8) = r2;" \
	"*(u64 *)(r6 + 16) = r3;" \
	"*(u64 *)(r6 + 24) = r4;" \
	"*(u64 *)(r6 + 32) = r5;"

SEC("tc")
__naked int irq_fastcall_preserve(void)
{
	asm volatile (
		"r7 = *(u32 *)(r1 + 8); r6 = %[saved_regs] ll;"
		"r1 = r10; r1 += -8;"
		IRQ_SET_REGS IRQ_SPILLS
		"call %[bpf_local_irq_save];"
		IRQ_FILLS IRQ_CAPTURE_REGS
		"r6 += 40; r1 = r10; r1 += -8;"
		IRQ_SET_REGS IRQ_SPILLS
		"call %[bpf_local_irq_restore];"
		IRQ_FILLS IRQ_CAPTURE_REGS
		"r0 = 0; exit;"
		:
		: __imm(bpf_local_irq_save), __imm(bpf_local_irq_restore), __imm_addr(saved_regs)
		: __clobber_all);
}

char _license[] SEC("license") = "GPL";
