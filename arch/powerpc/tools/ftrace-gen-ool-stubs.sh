#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later

# Error out on error
set -e

is_enabled() {
	grep -q "^$1=y" include/config/auto.conf
}

vmlinux_o=${2}
arch_vmlinux_o=${3}
arch_vmlinux_S=$(dirname ${arch_vmlinux_o})/$(basename ${arch_vmlinux_o} .o).S

RELOCATION=R_PPC64_ADDR64
if is_enabled CONFIG_PPC32; then
	RELOCATION=R_PPC_ADDR32
fi

num_ool_stubs_text=$(${CROSS_COMPILE}objdump -r -j __patchable_function_entries ${vmlinux_o} |
		     grep -v ".init.text" | grep "${RELOCATION}" | wc -l)
num_ool_stubs_inittext=$(${CROSS_COMPILE}objdump -r -j __patchable_function_entries ${vmlinux_o} |
			 grep ".init.text" | grep "${RELOCATION}" | wc -l)

num_ool_stubs_text_builtin=${1}
num_ool_stubs_text_end=$(expr ${num_ool_stubs_text} - ${num_ool_stubs_text_builtin})

cat > ${arch_vmlinux_S} <<EOF
#include <asm/asm-offsets.h>
#include <asm/ppc_asm.h>
#include <linux/linkage.h>

.pushsection .tramp.ftrace.text,"aw"
SYM_DATA(ftrace_ool_stub_text_end_count, .long ${num_ool_stubs_text_end})

SYM_START(ftrace_ool_stub_text_end, SYM_L_GLOBAL, .balign SZL)
	.space ${num_ool_stubs_text_end} * FTRACE_OOL_STUB_SIZE
SYM_CODE_END(ftrace_ool_stub_text_end)
.popsection

.pushsection .tramp.ftrace.init,"aw"
SYM_DATA(ftrace_ool_stub_inittext_count, .long ${num_ool_stubs_inittext})

SYM_START(ftrace_ool_stub_inittext, SYM_L_GLOBAL, .balign SZL)
	.space ${num_ool_stubs_inittext} * FTRACE_OOL_STUB_SIZE
SYM_CODE_END(ftrace_ool_stub_inittext)
.popsection
EOF

${CC} ${NOSTDINC_FLAGS} ${LINUXINCLUDE} ${KBUILD_CPPFLAGS} \
      ${KBUILD_AFLAGS} ${KBUILD_AFLAGS_KERNEL} \
      -c -o ${arch_vmlinux_o} ${arch_vmlinux_S}
