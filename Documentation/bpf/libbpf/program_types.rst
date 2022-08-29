.. SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

.. _program_types_and_elf:

Program Types and ELF Sections
==============================

The table below lists the program types, their attach types where relevant and the ELF section
names supported by libbpf for them. The ELF section names follow these rules:

- ``type`` is an exact match, e.g. ``SEC("socket")``
- ``type+`` means it can be either exact ``SEC("type")`` or well-formed ``SEC("type/extras")``
  with a ‘``/``’ separator between ``type`` and ``extras``.

When ``extras`` are specified, they provide details of how to auto-attach the BPF program.
The format of ``extras`` depends on the program type, e.g. ``SEC("tracepoint/<category>/<name>")``
for tracepoints or ``SEC("usdt/<path-to-binary>:<usdt_provider>:<usdt_name>")`` for USDT probes.

..
  program_types.csv is generated from tools/lib/bpf/libbpf.c and is fomatted like this:
    Program Type,Attach Type,ELF Section Name,Sleepable
    ``BPF_PROG_TYPE_SOCKET_FILTER``,,``socket``,
    ``BPF_PROG_TYPE_SK_REUSEPORT``,``BPF_SK_REUSEPORT_SELECT_OR_MIGRATE``,``sk_reuseport/migrate``,
    ``BPF_PROG_TYPE_SK_REUSEPORT``,``BPF_SK_REUSEPORT_SELECT``,``sk_reuseport``,
    ``BPF_PROG_TYPE_KPROBE``,,``kprobe+``,
    ``BPF_PROG_TYPE_KPROBE``,,``uprobe+``,
    ``BPF_PROG_TYPE_KPROBE``,,``uprobe.s+``,Yes

.. csv-table:: Program Types and Their ELF Section Names
   :file: ../../output/program_types.csv
   :widths: 40 30 20 10
   :header-rows: 1
