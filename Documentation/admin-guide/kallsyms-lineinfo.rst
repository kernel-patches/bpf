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

Module Support
==============

``CONFIG_KALLSYMS_LINEINFO_MODULES`` extends the feature to loadable kernel
modules.  When enabled, each ``.ko`` is post-processed at build time to embed
a ``.mod_lineinfo`` section containing the same kind of address-to-source
mapping.

Enable in addition to the base options::

    CONFIG_MODULES=y
    CONFIG_KALLSYMS_LINEINFO_MODULES=y

Stack traces from module code will then include annotations::

    my_driver_func+0x30/0x100 [my_driver] (drivers/foo/bar.c:123)

The ``.mod_lineinfo`` section is loaded into read-only module memory alongside
the module text.  No additional runtime memory allocation is required; the data
is freed when the module is unloaded.

Memory Overhead
===============

The vmlinux lineinfo tables are stored in ``.rodata`` and typically add
approximately 10-15 MiB to the kernel image for a standard configuration
(~4.6 million DWARF line entries, ~2-3 bytes per entry after delta
compression).

Per-module lineinfo adds approximately 2-3 bytes per DWARF line entry to each
``.ko`` file.

Known Limitations
=================

- **4 GiB offset limit**: Address offsets from ``_text`` (vmlinux) or
  ``.text`` base (modules) are stored as 32-bit values.  Entries beyond
  4 GiB are skipped at build time with a warning.
- **65535 file limit**: Source file IDs are stored as 16-bit values.  Builds
  with more than 65535 unique source files will fail with an error.
- **No assembly annotations**: Functions implemented in assembly that lack
  DWARF ``.debug_line`` data are not annotated.
- **No init text**: For modules, functions in ``.init.text`` are not annotated
  because that memory is freed after module initialization.
