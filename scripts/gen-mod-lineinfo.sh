#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# gen-mod-lineinfo.sh - Embed source line info into a kernel module (.ko)
#
# Reads DWARF from the .ko, generates a .mod_lineinfo section, and
# embeds it back into the .ko.  Modeled on scripts/gen-btf.sh.

set -e

if [ $# -ne 1 ]; then
	echo "Usage: $0 <module.ko>" >&2
	exit 1
fi

KO="$1"

cleanup() {
	rm -f "${KO}.lineinfo.S" "${KO}.lineinfo.o" "${KO}.lineinfo.bin"
}
trap cleanup EXIT

case "${KBUILD_VERBOSE}" in
*1*)
	set -x
	;;
esac

# Generate assembly from DWARF -- if it fails (no DWARF), silently skip
if ! ${objtree}/scripts/gen_lineinfo --module "${KO}" > "${KO}.lineinfo.S"; then
	exit 0
fi

# Compile assembly to object file
${CC} ${NOSTDINC_FLAGS} ${LINUXINCLUDE} ${KBUILD_CPPFLAGS} \
	${KBUILD_AFLAGS} ${KBUILD_AFLAGS_MODULE} \
	-c -o "${KO}.lineinfo.o" "${KO}.lineinfo.S"

# Extract raw section content
${OBJCOPY} -O binary --only-section=.mod_lineinfo \
	"${KO}.lineinfo.o" "${KO}.lineinfo.bin"

# Embed into the .ko with alloc,readonly flags
${OBJCOPY} --add-section ".mod_lineinfo=${KO}.lineinfo.bin" \
	--set-section-flags .mod_lineinfo=alloc,readonly \
	"${KO}"

exit 0
