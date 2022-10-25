#!/bin/bash
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

# This script verifies that patterns for header guard inference
# specified in scripts/infer_header_guards.pl cover all uapi headers.
# To achieve this the infer_header_guards.pl is invoked the same way
# it is invoked from link-vmlinux.sh but with --report-failures flag.

kernel_dir=$(dirname $0)/../../../../

# The SRCARCH is defined in tools/scripts/Makefile.arch, thus use a
# temporary makefile to get access to this variable.
fake_makefile=$(cat <<EOF
include tools/scripts/Makefile.arch
default:
	scripts/infer_header_guards.pl --report-failures \
		include/uapi \
		include/generated/uapi \
		arch/\$(SRCARCH)/include/uapi \
		arch/\$(SRCARCH)/include/generated/uapi 1>/dev/null
EOF
)

# The infer_header_guards.pl script prints inferred guards to stdout,
# redirecting stdout to /dev/null to see only error messages.
echo "$fake_makefile" | make -C $kernel_dir -f - 1>/dev/null
if [ "$?" == "0" ]; then
	echo "all good"
	exit 0
fi

# Failures are already reported by infer_header_guards.pl
exit 1
