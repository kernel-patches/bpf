=================================
Linux Security Module Development
=================================

Based on https://lore.kernel.org/r/20071026073721.618b4778@laptopd505.fenrus.org,
a new LSM is accepted into the kernel when its intent (a description of
what it tries to protect against and in what cases one would expect to
use it) has been appropriately documented in ``Documentation/admin-guide/LSM/``.
This allows an LSM's code to be easily compared to its goals, and so
that end users and distros can make a more informed decision about which
LSMs suit their requirements.

For extensive documentation on the available LSM hook interfaces, please
see ``security/security.c`` and associated structures:

.. kernel-doc:: security/security.c
   :export:

LSM policy kptr hooks and BPF kfuncs
====================================

The LSM framework implements an interface for individual LSMs to
expose their configuration through BPF kfuncs and kptrs. An LSM
may not export any kfunc or other BPF interface directly.

An LSM wishing to expose a BPF kfunc must reuse an existing security
hook or implement a new sufficiently generic LSM hook for the desired
interface. The hooks are then called from kfunc definitions in
``kernel/bpf``. This allows LSM hooks to remain sufficiently generic
while allowing BPF programs to take advantage of the strong typing
and runtime checking offered by the BPF verifier.

The LSM providing an operation implements the operation's hook with
``LSM_HOOK_INIT()`` like any other hook. A BPF program calling an
LSM kfunc therefore reaches the LSM the same way every other
kernel caller does: through an LSM hook. The hooks backing kfuncs
follow the usual rules for new LSM hooks: their contract must be
LSM agnostic so that other LSMs could provide a meaningful
implementation of the same operation.

Whether the LSM providing an operation is built in and active is a
runtime property: the kfuncs are always registered when
``CONFIG_BPF_LSM`` is enabled. BPF program loading is thus
independent of the boot-time LSM configuration.
