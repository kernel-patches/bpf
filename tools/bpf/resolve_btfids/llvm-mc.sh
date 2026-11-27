#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# usage: llvm-mc.sh SRCARCH [cxxflags | libs]
#
# text_mc.cpp reads the machine code of the kernel arch SRCARCH with LLVM's MC
# layer. Fail, and say why, if this host lacks what it takes to build it.
# CONFIG_BPF_FMODRET_SCAN depends on that. Each Kconfig run pays for it, so it is
# one run of llvm-config. Whether text_mc.cpp works with this LLVM shows when the
# tool is built, and in text_arch_init() when it starts.
#
# For the Makefile print the flags to compile text_mc.cpp, or the libraries.
#
# The host's LLVM need not be the one which compiles the kernel, if any does.

die()
{
	echo "$0: $*" >&2
	exit 1
}

case "$1" in
x86)	target=X86 ;;
arm64)	target=AArch64 ;;
*)	die "no text_mc_$1.c" ;;
esac
print=$2

if [ -z "$LLVM_CONFIG" ]; then
	case "$LLVM" in
	*/)	LLVM_CONFIG=${LLVM}llvm-config ;;
	-*)	LLVM_CONFIG=llvm-config$LLVM ;;
	*)	LLVM_CONFIG=llvm-config ;;
	esac
fi

command -v ${HOSTCXX:-g++} > /dev/null || die "no C++ compiler ${HOSTCXX:-g++}"
set -- $($LLVM_CONFIG --version --includedir --targets-built 2> /dev/null)
[ $# -gt 2 ] || die "cannot run $LLVM_CONFIG"
[ "${1%%.*}" -ge 17 ] || die "$LLVM_CONFIG is LLVM $1, not 17 or later"
[ -e "$2/llvm/MC/MCInstrDesc.h" ] || die "$2 lacks the headers of LLVM $1"
case " $* " in
*" $target "*)	;;
*)	die "$LLVM_CONFIG, LLVM $1, lacks the target $target" ;;
esac

case "$print" in
cxxflags)
	echo "$($LLVM_CONFIG --cxxflags) -DMC_TARGET=$target"
	;;
libs)
	# A static link starts faster, which counts for each module, and does not tie the
	# tool, which is shipped for the build of external modules, to a shared library
	set -- --ldflags --libs --system-libs ${target}Desc ${target}Disassembler ${target}Info
	libs=$($LLVM_CONFIG --link-static "$@" 2> /dev/null) ||
	libs=$($LLVM_CONFIG --link-shared "$@") || die "no libraries of LLVM"
	echo $libs -lstdc++ -lm
	;;
esac
