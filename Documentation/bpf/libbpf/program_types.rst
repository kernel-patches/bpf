.. SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

.. _program_types_and_elf:

Program Types  and ELF Sections
===============================

The table below lists the program types, their attach types where relevant and the ELF section
names supported by libbpf for them. The ELF section names follow these rules:

- ``type`` is an exact match, e.g. ``SEC("socket")``
- ``type+`` means it can be either exact ``SEC("type")`` or well-formed ``SEC("type/extras")``
  with a ‘``/``’ separator, e.g. ``SEC("tracepoint/syscalls/sys_enter_open")``

.. csv-table:: Program Types and Their ELF Section Names
   :file: ../../output/program_types.csv
   :widths: 40 30 20 10
   :header-rows: 1
