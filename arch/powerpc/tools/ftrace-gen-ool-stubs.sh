#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later

# Error out on error
set -e

is_enabled() {
	grep -q "^$1=y" include/config/auto.conf
}

vmlinux_o=${1}
arch_vmlinux_S=${2}

RELOCATION=R_PPC64_ADDR64
if is_enabled CONFIG_PPC32; then
	RELOCATION=R_PPC_ADDR32
fi

num_ool_stubs_text=$(${CROSS_COMPILE}objdump -r -j __patchable_function_entries ${vmlinux_o} |
		     grep -v ".init.text" | grep "${RELOCATION}" | wc -l)
num_ool_stubs_inittext=$(${CROSS_COMPILE}objdump -r -j __patchable_function_entries ${vmlinux_o} |
			 grep ".init.text" | grep "${RELOCATION}" | wc -l)

cat > ${arch_vmlinux_S} <<EOF
#include <asm/asm-offsets.h>
#include <linux/linkage.h>

.pushsection .tramp.ftrace.text,"aw"
SYM_DATA(ftrace_ool_stub_text_end_count, .long ${num_ool_stubs_text})

SYM_CODE_START(ftrace_ool_stub_text_end)
	.space ${num_ool_stubs_text} * FTRACE_OOL_STUB_SIZE
SYM_CODE_END(ftrace_ool_stub_text_end)
.popsection

.pushsection .tramp.ftrace.init,"aw"
SYM_DATA(ftrace_ool_stub_inittext_count, .long ${num_ool_stubs_inittext})

SYM_CODE_START(ftrace_ool_stub_inittext)
	.space ${num_ool_stubs_inittext} * FTRACE_OOL_STUB_SIZE
SYM_CODE_END(ftrace_ool_stub_inittext)
.popsection
EOF
