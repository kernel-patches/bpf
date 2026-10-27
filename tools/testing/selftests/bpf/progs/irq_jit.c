#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

extern void bpf_local_irq_save(unsigned long *) __ksym;
extern void bpf_local_irq_restore(unsigned long *) __ksym;
extern bool CONFIG_TRACE_IRQFLAGS __kconfig __weak;
extern bool CONFIG_PARAVIRT_XXL __kconfig __weak;
extern bool CONFIG_ARM64_DEBUG_PRIORITY_MASKING __kconfig __weak;

static __always_inline int irq_jit_result(void)
{
	bool fallback = CONFIG_TRACE_IRQFLAGS;

#if defined(__TARGET_ARCH_x86)
	fallback |= CONFIG_PARAVIRT_XXL;
#elif defined(__TARGET_ARCH_arm64)
	fallback |= CONFIG_ARM64_DEBUG_PRIORITY_MASKING;
#else
	fallback = true;
#endif
	return fallback;
}

SEC("tc")
int irq_jit_basic(struct __sk_buff *ctx)
{
	unsigned long outer_flags, inner_flags;

	bpf_local_irq_save(&outer_flags);
	bpf_local_irq_save(&inner_flags);
	bpf_local_irq_restore(&inner_flags);
	bpf_local_irq_restore(&outer_flags);
	return ctx->len ? irq_jit_result() : 2;
}

static __noinline void irq_jit_nested(void)
{
	unsigned long flags;

	bpf_local_irq_save(&flags);
	bpf_local_irq_restore(&flags);
}

SEC("tc")
int irq_jit_subprog(struct __sk_buff *ctx)
{
	unsigned long flags;

	bpf_local_irq_save(&flags);
	irq_jit_nested();
	bpf_local_irq_restore(&flags);
	return ctx->len ? irq_jit_result() : 2;
}

char _license[] SEC("license") = "GPL";
