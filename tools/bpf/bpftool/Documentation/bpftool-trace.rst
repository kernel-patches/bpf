.. SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

============
bpftool-trace
============
-------------------------------------------------------------------------------
tool to create BPF tracepoints
-------------------------------------------------------------------------------

:Manual section: 8

.. include:: substitutions.rst

SYNOPSIS
========

	**bpftool** [*OPTIONS*] **trace** *COMMAND*

	*OPTIONS* := { |COMMON_OPTIONS| }

	*COMMANDS* := { **pin** | **help** }

ITER COMMANDS
===================

|	**bpftool** **trace pin** *OBJ* *PATH*
|	**bpftool** **trace help**
|
|	*OBJ* := /a/file/of/bpf_tp_target.o

DESCRIPTION
===========
	**bpftool trace pin** *OBJ* *PATH*
                  A bpf raw tracepoint allows a tracepoint to provide a safe
                  buffer that can be read or written from a bpf program.

		  The *pin* command attaches a bpf raw tracepoint from *OBJ*,
		  and pin it to *PATH*. The *PATH* should be located
		  in *bpffs* mount. It must not contain a dot
		  character ('.'), which is reserved for future extensions
		  of *bpffs*.

	**bpftool trace help**
		  Print short help message.

OPTIONS
=======
	.. include:: common_options.rst

EXAMPLES
========
**# bpftool trace pin bpf_mtd_chip_mockup.o /sys/fs/bpf/mtd_chip_mockup**

::

   Attach to the raw tracepoint from bpf_mtd_chip_mockup.o and pin it
   to /sys/fs/bpf/mtd_chip_mockup
