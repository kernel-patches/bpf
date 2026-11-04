.. SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

===============
bpftool-fmodret
===============
-------------------------------------------------------------------------------
tool to inspect BPF fmod_ret targets
-------------------------------------------------------------------------------

:Manual section: 8

.. include:: substitutions.rst

SYNOPSIS
========

**bpftool** [*OPTIONS*] **fmodret** *COMMAND*

*OPTIONS* := { |COMMON_OPTIONS| | { **-B** | **--base-btf** } *FILE* }

*COMMANDS* := { **list** | **show** | **help** }

FMODRET COMMANDS
================

| **bpftool** **fmodret list** [*OBJECT*]
| **bpftool** **fmodret show** *FUNC* [*OBJECT*]
| **bpftool** **fmodret help**
|
| *FUNC* := { **name** *NAME* | **id** *BTF_ID* }
| *OBJECT* := { **file** *FILE* | **vmlinux** | **module** *NAME* }

DESCRIPTION
===========

bpftool fmodret list [*OBJECT*]
    List the fmod_ret targets, the functions which the kernel build tags with
    the **bpf_fmodret** BTF decl tag, in vmlinux and in loaded modules. Each
    entry contains the BTF ID of the function, its name and the name of the
    object it belongs to. Targets which sleepable programs may attach to are
    marked **sleepable**.

    With **file**, read the BTF from *FILE* (for example a vmlinux image or a
    **BTF** file) instead of the running kernel. With **vmlinux** or
    **module**, list only the targets of vmlinux or of the module *NAME*.

    With **--json**, each entry contains **btf_id**, **name**, **owner** and
    **sleepable** fields.

    The verifier also accepts functions by its static rules, such as the error
    injection list or **security_** hooks. Such functions are listed only if
    the kernel build tagged them. Even if they are listed, the restrictions of
    their **bpf_fmodret_retval:** tags do not apply to them: programs may
    return any value, and sleepable programs may attach to some of them without
    the **sleepable** mark. This may change in the future by either not listing
    them, or listing them without restrictions. Normal verifier and tracing
    checks apply to all of them.

bpftool fmodret show *FUNC* [*OBJECT*]
    Show the function named *NAME* or with BTF ID *BTF_ID* in detail. It does
    not have to be a target. A name may belong to several functions, for
    example to functions of different modules. A BTF ID is looked up in
    vmlinux, unless **module** or **file** is given. *OBJECT* is as for
    **list**.

    Besides the BTF ID, the name and the object, show the prototype of the
    function and if it is a target: **found by the kernel build**, **declared**
    or **not tagged**. For a target show if sleepable programs may attach to it
    and the values which programs may return: 0 and the values of its
    **bpf_fmodret_retval:** tag with the names of the errors on the host, or
    **any** for a declared target. A tag which the verifier would reject,
    malformed, not the only one or with values which the return type cannot
    hold, is shown as invalid. The values do not apply to a function which the
    static rules allow, see **list**. For the running kernel, also show the
    type of the entry of the function in the error injection list, if the list
    is available in debugfs.

    With **--json**, each function contains **btf_id**, **name**, **owner**,
    **prototype**, **target** (**found**, **declared** or **none**) and
    **sleepable** fields, a **retval** array for a target found by the build
    with the values programs may return, 0 included, or a **retval_error**
    string if its tag is invalid, and an **error_injection** field if the
    function is in the error injection list. A BTF ID gives one function, a
    name an array of them.

bpftool fmodret help
    Print short help message.

OPTIONS
========

.. include:: common_options.rst

-B, --base-btf *FILE*
    Pass the base BTF of a split BTF *FILE*, usually the BTF of vmlinux. Raw
    BTF of a module needs it. A module image may carry the base it was built
    against in its **.BTF.base** section instead, but its BTF IDs then differ
    from those of the running kernel.

EXAMPLES
========

**# bpftool fmodret show name bpf_testmod_retval_join module bpf_test_retval**

::

  123456  bpf_testmod_retval_join (bpf_test_retval)
          int bpf_testmod_retval_join(int *result, int value)
          target: found by the kernel build
          sleepable: no
          retval: 0, -34 (ERANGE), -22 (EINVAL)
