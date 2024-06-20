#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later

# Error out on error
set -e

is_enabled() {
	grep -q "^$1=y" include/config/auto.conf
}

vmlinux_o=${1}
arch_vmlinux_o=${2}
arch_vmlinux_S=$(dirname ${arch_vmlinux_o})/$(basename ${arch_vmlinux_o} .o).S

RELOCATION=R_PPC64_ADDR64
if is_enabled CONFIG_PPC32; then
	RELOCATION=R_PPC_ADDR32
fi

num_pfe_stubs_text=$(${CROSS_COMPILE}objdump -r -j __patchable_function_entries ${vmlinux_o} |
		     grep -v ".init.text" | grep "${RELOCATION}" | wc -l)
num_pfe_stubs_inittext=$(${CROSS_COMPILE}objdump -r -j __patchable_function_entries ${vmlinux_o} |
			 grep ".init.text" | grep "${RELOCATION}" | wc -l)

cat > ${arch_vmlinux_S} <<EOF
#include <asm/asm-offsets.h>
#include <asm/ppc_asm.h>
#include <linux/linkage.h>

.pushsection .tramp.ftrace.text,"aw"
SYM_DATA(ftrace_pfe_stub_text_count, .long ${num_pfe_stubs_text})

SYM_START(ftrace_pfe_stub_text, SYM_L_GLOBAL, .balign SZL)
	.space ${num_pfe_stubs_text} * FTRACE_PFE_STUB_SIZE
SYM_CODE_END(ftrace_pfe_stub_text)
.popsection

.pushsection .tramp.ftrace.init,"aw"
SYM_DATA(ftrace_pfe_stub_inittext_count, .long ${num_pfe_stubs_inittext})

SYM_START(ftrace_pfe_stub_inittext, SYM_L_GLOBAL, .balign SZL)
	.space ${num_pfe_stubs_inittext} * FTRACE_PFE_STUB_SIZE
SYM_CODE_END(ftrace_pfe_stub_inittext)
.popsection
EOF

${CC} ${NOSTDINC_FLAGS} ${LINUXINCLUDE} ${KBUILD_CPPFLAGS} \
      ${KBUILD_AFLAGS} ${KBUILD_AFLAGS_KERNEL} \
      -c -o ${arch_vmlinux_o} ${arch_vmlinux_S}
