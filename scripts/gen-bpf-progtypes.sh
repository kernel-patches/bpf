#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2022 Red Hat.
#
# Generate a .csv table of BPF program types

if [ "$#" -lt 2 ]; then
    echo "Usage: gen-bpf-progtypes.sh </path/to/libbpf.c> </path/to/generated.csv>"
    exit 1
fi

# Extract program types and properties from the section definitions in libbpf.c such as
# SEC_DEF("socket", SOCKET_FILTER, 0, SEC_NONE) to generate a table of program types in
# .csv format.
#
# Here is a sample of the generated output that includes .rst formatting:
#
#  Program Type,Attach Type,ELF Section Name,Sleepable
#  ``BPF_PROG_TYPE_SOCKET_FILTER``,,``socket``,
#  ``BPF_PROG_TYPE_SK_REUSEPORT``,``BPF_SK_REUSEPORT_SELECT_OR_MIGRATE``,``sk_reuseport/migrate``,
#  ``BPF_PROG_TYPE_SK_REUSEPORT``,``BPF_SK_REUSEPORT_SELECT``,``sk_reuseport``,
#  ``BPF_PROG_TYPE_KPROBE``,,``kprobe+``,
#  ``BPF_PROG_TYPE_KPROBE``,,``uprobe+``,
#  ``BPF_PROG_TYPE_KPROBE``,,``uprobe.s+``,Yes

awk -F'[",[:space:]]+' \
    'BEGIN { print "Program Type,Attach Type,ELF Section Name,Sleepable" }
    /SEC_DEF\(\"/ && !/SEC_DEPRECATED/ {
    type = "``BPF_PROG_TYPE_" $4 "``"
    attach = index($5, "0") ? "" : "``" $5 "``";
    section = "``" $3 "``"
    sleepable = index($0, "SEC_SLEEPABLE") ? "Yes" : "";
    print type "," attach "," section "," sleepable }' $1 | sort > $2
