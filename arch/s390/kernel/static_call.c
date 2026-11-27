// SPDX-License-Identifier: GPL-2.0

#include <linux/text-patching.h>
#include <linux/static_call.h>
#include <linux/memory.h>
#include <asm/uaccess.h>

struct insn_ril {
	u16	opc;
	s32	ri2;
} __packed;

void arch_static_call_transform(void *site, void *tramp, void *func, bool tail)
{
	struct insn_ril *insn = tramp;
	void *literal;

	guard(mutex)(&text_mutex);
	literal = tramp + insn->ri2 * 2;
	if (!func)
		func = __static_call_return0;
	s390_kernel_write(literal, &func, sizeof(func));
}
EXPORT_SYMBOL_GPL(arch_static_call_transform);
