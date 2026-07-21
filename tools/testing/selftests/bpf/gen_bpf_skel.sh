#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Link BPF object file(s) with "bpftool gen object" and generate a
# skeleton (or light skeleton) header from the result.
#
# Usage:
#   BPFTOOL=<bpftool> gen_bpf_skel.sh --name NAME --skel OUT [options] OBJ...
#
#   --name NAME       skeleton object name ("name NAME" for bpftool)
#   --skel OUT        output header ("foo.skel.h" or "foo.lskel.h")
#   --subskel OUT     also generate a subskeleton header into OUT
#   --lskel           generate a light skeleton (bpftool gen skeleton -L)
#   --sign 'ARGS'     extra "gen skeleton" args for signing (-S -k .. -i ..)
#   --tag TAG         build-log tag, e.g. "test_progs-no_alu32"
#   --infix STR       intermediate file infix (default: linked). Callers
#                     generating both a .skel.h and a .lskel.h from the
#                     same .bpf.o MUST use distinct infixes, or parallel
#                     builds race on the intermediate files.
#   --no-determinism-check
#                     link the inputs once instead of three times.
#                     By default the object is re-linked twice more and
#                     the 2nd and 3rd results compared, as a regression
#                     test for the determinism of "bpftool gen object".
#
# The bpftool binary is taken from $BPFTOOL (default: bpftool from PATH).
# On failure all outputs and intermediates are removed and the script
# exits non-zero; permissive-mode skipping is the caller's business
# (see skip_on_fail in Makefile.buildvars).

set -u

bpftool=${BPFTOOL:-bpftool}
name='' skel='' subskel='' tag='' sign_args='' infix=linked
lskel=0 det_check=1

while [ $# -gt 0 ]; do
	case "$1" in
	--name)		name=$2; shift 2 ;;
	--skel)		skel=$2; shift 2 ;;
	--subskel)	subskel=$2; shift 2 ;;
	--tag)		tag=$2; shift 2 ;;
	--infix)	infix=$2; shift 2 ;;
	--sign)		sign_args=$2; shift 2 ;;
	--lskel)	lskel=1; shift ;;
	--no-determinism-check) det_check=0; shift ;;
	--)		shift; break ;;
	-*)		echo "$0: unknown option: $1" >&2; exit 1 ;;
	*)		break ;;
	esac
done

if [ -z "$name" ] || [ -z "$skel" ] || [ $# -eq 0 ]; then
	echo "usage: $0 --name NAME --skel OUT [options] OBJ..." >&2
	exit 1
fi

base=${skel%.skel.h}
base=${base%.lskel.h}
t1=$base.${infix}1.o
t2=$base.${infix}2.o
t3=$base.${infix}3.o

fail() {
	rm -f "$skel" ${subskel:+"$subskel"} "$t1" "$t2" "$t3"
	exit 1
}

if [ $# -gt 1 ]; then
	printf '  %-12s %s\n' 'LINK-BPF' "${tag:+[$tag] }$(basename "$base").bpf.o" >&2
fi
printf '  %-12s %s\n' 'GEN-SKEL' "${tag:+[$tag] }$(basename "$skel")" >&2

"$bpftool" gen object "$t1" "$@" || fail
final=$t1
if [ "$det_check" -eq 1 ]; then
	"$bpftool" gen object "$t2" "$t1" || fail
	"$bpftool" gen object "$t3" "$t2" || fail
	if ! cmp -s "$t2" "$t3"; then
		echo "$0: bpftool gen object is not deterministic for $skel" >&2
		fail
	fi
	final=$t3
fi

flags=
[ "$lskel" -eq 1 ] && flags=-L
# $sign_args intentionally unquoted: it is a list of bpftool arguments
# shellcheck disable=SC2086
"$bpftool" gen skeleton $sign_args $flags "$final" name "$name" > "$skel" || fail

if [ -n "$subskel" ]; then
	"$bpftool" gen subskeleton "$final" name "$name" > "$subskel" || fail
fi

rm -f "$t1" "$t2" "$t3"
exit 0
