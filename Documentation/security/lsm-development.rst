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

LSM policy objects and BPF kfuncs
=================================

The LSM framework implements an interface for individual LSMs to
expose their policy through BPF kfuncs and kptrs. An LSM may not
export any kfunc or other BPF interface directly.

An LSM opts in by embedding ``struct lsm_policy_object`` in one of
its own objects, setting its ``lsmid`` to the LSM's ``LSM_ID_*``
value and its ``type`` to a nonzero value of the LSM's choosing, and
implementing the policy object hooks (``policy_object_from_fd``,
``policy_object_get``, ``policy_object_put``, and per-operation hooks
such as ``bprm_apply_policy_object``) like any other hook, resolving
the containing object with ``container_of()``. The ``type`` namespace
is private to the owning LSM, which uses it to tell its own policy
object kinds apart; the framework never interprets it, and 0 is
reserved as "unset".

The kfuncs, defined once in ``security/bpf_lsm_kfuncs.c``, dispatch
each call on an object to the single LSM matching its ``lsmid``. The
fd translation has no object yet: the framework offers the fd to
every ``policy_object_from_fd`` implementation in turn, and an LSM
declines a fd that is not one of its own with ``-EOPNOTSUPP``; any
other error fails the translation. A program that expects a policy of
a specific LSM can read the returned object's ``lsmid``. Either way,
a BPF program reaches an LSM the same way every other kernel caller
does, through an LSM hook, while the BPF verifier tracks the object
as a referenced kptr.

An LSM opting in must satisfy the lifetime contract that BPF's
execution model imposes: the containing object is reference counted,
``policy_object_get`` acquires with inc-not-zero semantics and fails
once the count dropped to zero, ``policy_object_put`` may be called
from contexts that cannot sleep (map destructors), and the object's
memory is freed only after an RCU grace period, as programs load
policy object kptrs from BPF maps under RCU. Hooks for operations an
LSM does not provide are simply not implemented: the corresponding
kfunc then fails with ``-EOPNOTSUPP`` at runtime. Whether the LSM
providing an operation is built in and active is likewise a runtime
property: the kfuncs are always registered when ``CONFIG_BPF_LSM`` is
enabled, so BPF program loading is independent of the boot-time LSM
configuration.

.. kernel-doc:: security/bpf_lsm_kfuncs.c
   :identifiers: bpf_lsm_policy_acquire
                 bpf_lsm_policy_apply_bprm
                 bpf_lsm_policy_from_fd
                 bpf_lsm_policy_release
