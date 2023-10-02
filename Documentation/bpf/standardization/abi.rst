===================================================
BPF ABI Recommended Conventions and Guidelines v1.0
===================================================

An application binary interface (ABI) defines the requirements that one or more binary software
objects must meet in order to guarantee that they can interoperate and/or use the resources provided
by operating systems/hardware combinations.  (For alternate definitions of ABI, see
[SYSVABI]_, [POWERPCABI]_)

The purpose of this document is to define an ABI which will define the extent to which compiled
eBPF programs are compatible with each other and the eBPF machine/processor [#]_ on which they
are executing.

The ABI is specified in two parts: a generic part and a processor-specific part.
A pairing of of generic ABI with the processor-specific ABI for a certain instantiation
of an eBPF machine represents a complete binary interface for eBPF programs executing
on that machine.

This document is a generic ABI and specifies the parameters and behavior common to all
instantiations of eBPF machines. In addition, it defines the details that must be specified by each
processor-specific ABI. 

These psABIs are the second part of the ABI. Each instantiation of an eBPF machine must
describe the mechanism through which binary interface compatibility is maintained with
respect to the issues highlighted by this document. However, the details that must be
defined by a psABI are a minimum -- a psABI may specify additional requirements for binary
interface compatibility on a platform.

.. contents::
.. sectnum::

How To Use This ABI
===================

Conformance
===========

Note: Red Hat specifies different levels of conformance over time [RHELABI]_.

Related Work
============
eBPF programs are not unique for the way that they operate on a virtualized machine and processor.
There are many programming languages that compile to an ISA that is specific to a virtual machine.
Like the specification presented herein, those languages and virtual machines also have ABIs.

For example, the Go programming language and the runtime included statically with each program compiled
from Go source code have a defined ABI [GOABI]_. Java programs compiled to bytecode follow a well-defined
ABI for interoperability with other compiled Java programs and libraries [JAVAABI]_. Programs compiled to
bytecode for execution as user applications on the Android operating system (OS) adhere to a bytecode
specification that shares much in common with an ABI [DALVIKABI]_. Finally, the Common Language Runtime (CLR)
designed to execute programs compiled to the Microsoft Intermediate Language (MSIL) has a fully specified
ABI [CLRABI]_.

Vocabulary
==========

#. Program: An eBPF Program is a self-contained set of eBPF instructions that execute
   on an eBPF processor.
#. Program Type: Every eBPF program has an associated type. The program type defines, among other things,
   a program's possible attach types.
#. Attach Type: An attach type defines the set of BPF hook points to which an eBPF
   program can attach.
#. BPF Hook Points: Places in a BPF-enabled component (e.g., the Linux Kernel, the Windows kernel) where
   an eBPF program may be attached.
#. eBPF Machine Instantiation: 
#. ABI-conforming system: A computer system that provides the binary sys- tem interface for application
   programs described in the System V ABI [SYSVABI]_.
#. ABI-conforming program: A program written to include only the system routines, commands, and other
   resources included in the ABI, and a program compiled into an executable file that has the formats
   and characteristics specified for such files in the ABI, and a program whose behavior complies with
   the rules given in the ABI [SYSVABI]_.
#. ABI-nonconforming program: A program which has been written to include system routines, commands, or
   other resources not included in the ABI, or a program which has been compiled into a format different
   from those specified in the ABI, or a program which does not behave as specified in the ABI [SYSVABI]_.
#. Undefined Behavior: Behavior that may vary from instance to instance or may change at some time in the future.
   Some undesirable programming practices are marked in the ABI as yielding undefined behavior [SYSVABI]_. 
#. Unspecified Property: A property of an entity that is not explicitly included or referenced in this specification,
   and may change at some time in the future. In general, it is not good practice to make a program depend
   on an unspecified property [SYSVABI]_.

Program Execution Environment
=============================

A loaded eBPF program is executed on an eBPF machine. That machine, physical or virtual, runs in a freestanding
or hosted environment [#]_.

eBPF Machine Freestanding Environment
-------------------------------------


eBPF Machine Hosted Environment
-------------------------------

A loaded eBPF program can be attached to a BPF hook point in a BPF-enabled application
compatible with the attach type of its program type. When the BPF-enabled application's
execution reaches a BPF hook point to which an eBPF program is attached, that program
begins execution on the eBPF machine at its first instruction. The contents of eBPF machine's
registers and memory at the time it starts execution are defined by the eBPF program's
type and attach point.

Processor Architecture
======================

This section describes the processor architecture available
to programs. It also defines the reference language data types, giving the
foundation for system interface specifications [SYSVABI]_

Registers
---------

General Purpose Registers
^^^^^^^^^^^^^^^^^^^^^^^^^
eBPF has 11 64-bit wide registers, `r0` - `r10`. The contents of the registers
at the beginning of an eBPF program's execution depend on the program's type.

Frame Pointer Register
^^^^^^^^^^^^^^^^^^^^^^
The use of a frame pointer by programs is not required. If, however, an eBPF program
does use a frame pointer, it must be stored in register `r10`.

Data Types
----------

Numeric Types
^^^^^^^^^^^^^

The eBPF machine supports 32- and 64-bit signed and unsigned integers. It does 
not support floating-point data types. All signed integers are represented in
twos-complement format where the sign bit is stored in the most-significant
bit.

Pointers
^^^^^^^^

Function Calling Sequence
=========================
This section defines the standard function calling sequence in a way that
accommodates exceptions, stack management, register (non)volatility, and access
to capabilities of the hosting environment (where applicable).

Functions in eBPF may define between 0 and 5 parameters. Each of the arguments in
a function call are passed in registers.

The eBPF calling convention is defined as:

* R0: return value from function calls, and exit value for eBPF programs
* R1 - R5: arguments for function calls
* R6 - R9: callee saved registers that function calls will preserve
* R10: read-only frame pointer to access stack

R0 - R5 are scratch registers and eBPF programs needs to spill/fill them if
necessary across calls.

Every function invocation proceeds as if it has exclusive access to an
implementation-defined amount of stack space. R10 is a pointer to the byte of
memory with the highest address in that stack space. The contents
of a function invocation's stack space do not persist between invocations.

**TODO** Discuss manufactured prologue and epilogue. Take language from the design FAQ.

Execution Environment Interface
===============================

When an eBPF program executes in a hosted environment, the hosted environment may make
available to eBPF programs certain capabilities. This section describes those capabilities
and the mechanism for accessing them.


Program Execution
=================

Program Return Values
---------------------

**NOTE** libbpf currently defines the return value of an ebpf program as a 32-bit unsigned integer.

Program Loading and Dynamic Linking
-----------------------------------
This section describes the object file information and system actions that create
running programs. Some information here applies to all systems; information specific
to one processor resides in sections marked accordingly [SYSVABI]_.

eBPF programs saved in ELF files must be loaded from storage and properly configured before
they can be executed on an eBPF machine. 

Program Loading (Processor-Specific)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Dynamic Linking
^^^^^^^^^^^^^^^

Global Offset Table (Processor-Specific)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Procedure Linkage Table (Processor-Specific)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Exception Handling
==================

eBPF Program Types
==================
**NOTE** This information may end up as a subsection somewhere else.

eBPF Maps
=========
**NOTE** This information may end up as a subsection somewhere else.

System Calls
============

**TODO**

C Programming Language Support
==============================

**NOTE** This section could be included in order to define the contents
of standardized processor-specific header files that would make it easier
for programmers to write programs.

Notes
=====
.. [#] The eBPF machine does not need to be a physical instantiation of a processor. In fact, many instantiations of eBPF machines are virtual.
.. [#] See the [CSTD]_ for the inspiration for this distinction.

References
==========

.. [SYSVABI] System V Application Binary Interface - Edition 4.1. SCO Developer Specs. The Santa Cruz Operation. 1997. https://www.sco.com/developers/devspecs/gabi41.pdf
.. [POWERPCABI] Developing PowerPC Embedded Application Binary Interface (EABI) Compliant Programs. PowerPC Embedded Processors Application Note. IBM. 1998. http://class.ece.iastate.edu/arun/Cpre381_Sp06/lab/labw12a/eabi_app.pdf
.. [GOABI] Go internal ABI specification. Go Source Code. No authors. 2023. https://go.googlesource.com/go/+/refs/heads/master/src/cmd/compile/abi-internal.md
.. [JAVAABI] The Java (r) Language Specification - Java SE 7 Edition. Gosling, James et. al. Oracle. 2013. https://docs.oracle.com/javase/specs/jls/se7/html/index.html
.. [DALVIKABI] Dalvik Bytecode. Android Core Runtime Documentation. No authors. Google. 2022. https://source.android.com/docs/core/runtime/dalvik-bytecode
.. [CLRABI] CLR ABI. The Book of the Runtime. No authors. Microsoft. 2023. https://github.com/dotnet/coreclr/blob/master/Documentation/botr/clr-abi.md. 
.. [CSTD] International Standard: Programming Languages - C. ISO/IEC. 2018. https://www.open-std.org/jtc1/sc22/wg14/www/docs/n2310.pdf.
.. [RHELABI] Red Hat Enterprise Linux 8: Application Compatibility Guide. Red Hat. 2023. https://access.redhat.com/articles/rhel8-abi-compatibility 


