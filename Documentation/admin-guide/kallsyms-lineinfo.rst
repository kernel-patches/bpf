.. SPDX-License-Identifier: GPL-2.0

====================================
Kallsyms Source Line Info (LINEINFO)
====================================

Overview
========

``CONFIG_KALLSYMS_LINEINFO`` embeds DWARF-derived source file and line number
mappings into the kernel image so that stack traces include
``(file.c:123)`` annotations next to each symbol.  This makes it significantly
easier to pinpoint the exact source location during debugging, without needing
to manually cross-reference addresses with ``addr2line``.

Enabling the Feature
====================

Enable the following kernel configuration options::

    CONFIG_KALLSYMS=y
    CONFIG_DEBUG_INFO=y
    CONFIG_KALLSYMS_LINEINFO=y

Build dependency: the host tool ``scripts/gen_lineinfo`` requires ``libdw``
from elfutils.  Install the development package:

- Debian/Ubuntu: ``apt install libdw-dev``
- Fedora/RHEL: ``dnf install elfutils-devel``
- Arch Linux: ``pacman -S elfutils``

Example Output
==============

Without ``CONFIG_KALLSYMS_LINEINFO``::

    Call Trace:
     <TASK>
     dump_stack_lvl+0x5d/0x80
     do_syscall_64+0x82/0x190
     entry_SYSCALL_64_after_hwframe+0x76/0x7e

With ``CONFIG_KALLSYMS_LINEINFO``::

    Call Trace:
     <TASK>
     dump_stack_lvl+0x5d/0x80 (lib/dump_stack.c:123)
     do_syscall_64+0x82/0x190 (arch/x86/entry/common.c:52)
     entry_SYSCALL_64_after_hwframe+0x76/0x7e

Note that assembly routines (such as ``entry_SYSCALL_64_after_hwframe``) are
not annotated because they lack DWARF debug information.

Memory Overhead
===============

The lineinfo tables are stored in ``.rodata`` and typically add approximately
44 MiB to the kernel image for a standard configuration (~4.6 million DWARF
line entries, ~10 bytes per entry after deduplication).

Known Limitations
=================

- **vmlinux only**: Only symbols in the core kernel image are annotated.
  Module symbols are not covered.
- **4 GiB offset limit**: Address offsets from ``_text`` are stored as 32-bit
  values.  Entries beyond 4 GiB from ``_text`` are skipped at build time with
  a warning.
- **65535 file limit**: Source file IDs are stored as 16-bit values.  Builds
  with more than 65535 unique source files will fail with an error.
- **No assembly annotations**: Functions implemented in assembly that lack
  DWARF ``.debug_line`` data are not annotated.
