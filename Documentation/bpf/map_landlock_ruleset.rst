.. SPDX-License-Identifier: GPL-2.0-only

==============================
BPF_MAP_TYPE_LANDLOCK_RULESET
==============================

``BPF_MAP_TYPE_LANDLOCK_RULESET`` is a specialized, array-backed map for
holding references to Landlock rulesets that were created from userspace.
It is meant to bridge BPF LSM policy selection with Landlock policy
enforcement: userspace creates a normal Landlock ruleset, inserts its file
descriptor into the map, and a BPF LSM program later looks up that ruleset and
applies it with a Landlock kfunc during ``execve()`` preparation.

BPF programs cannot create, inspect, or modify Landlock policy through this
map.  The looked-up object is exposed only as an opaque
``struct bpf_landlock_ruleset`` reference.

The map uses ``__u32`` keys as array indexes and stores one ruleset reference
per slot.  Like other array maps, its size is fixed at creation time and its
elements are preallocated.

Usage
=====

Kernel BPF
----------

.. note::
   This map type is only supported for BPF LSM programs.  In practice, it is
   useful for sleepable BPF LSM programs attached to
   ``bprm_creds_for_exec`` or ``bprm_creds_from_file``, because those are the
   hooks where the associated Landlock kfuncs are available.

bpf_map_lookup_elem()
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c

   void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)

Lookup returns a trusted pointer to an opaque ``struct bpf_landlock_ruleset``.
The verifier treats the result as a referenced BTF object, not as a pointer to
the raw ``__u32`` map value declared in the map definition.

Each successful lookup acquires a ruleset reference.  The BPF program must
release that reference with ``bpf_landlock_put_ruleset()`` on all paths after
the lookup succeeds.

The returned pointer is intended to be passed to
``bpf_landlock_restrict_binprm()``.  It is opaque and cannot be dereferenced
or inspected from BPF.

bpf_map_delete_elem()
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c

   long bpf_map_delete_elem(struct bpf_map *map, const void *key)

Delete removes the ruleset reference stored in the selected slot and drops the
map's own reference to that ruleset.

Landlock kfuncs
---------------

The map contains objects designed to work with the following Landlock kfuncs:

.. code-block:: c

   void bpf_landlock_put_ruleset(const struct bpf_landlock_ruleset *ruleset)

.. code-block:: c

   int bpf_landlock_restrict_binprm(struct linux_binprm *bprm,
                                    const struct bpf_landlock_ruleset *ruleset,
                                    __u32 flags)

``bpf_landlock_restrict_binprm()`` applies the looked-up ruleset to the new
program credentials that are being prepared for ``execve()``.  The ``flags``
argument supports the same logging and ``no_new_privs`` restriction flags as
``landlock_restrict_self()``, including
``LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS_EXECTIME``.  The
``LANDLOCK_RESTRICT_SELF_EXECTIME`` flag must not be passed from BPF because
``bpf_landlock_restrict_binprm()`` already applies the ruleset at exec time.
When ``LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS_EXECTIME`` is used from BPF,
``no_new_privs`` is staged through the exec context and committed only after
exec reaches point-of-no-return.  This avoids side effects on failed
executions or ``AT_EXECVE_CHECK`` while ensuring that the resulting task cannot
gain more privileges through later exec transitions.

Userspace
---------

bpf_map_update_elem()
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c

   int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags)

Userspace populates the map by writing a Landlock ruleset file descriptor into
the selected slot.  The map uses FD-array update semantics:

- ``key`` points to a ``__u32`` array index.
- ``value`` points to a ``__u32`` containing the ruleset file descriptor.
- ``flags`` must be ``BPF_ANY``.

The supplied file descriptor must refer to a valid Landlock ruleset.

Userspace lookup of map contents is not supported for this map type.

Example
=======

Kernel BPF
----------

The following snippet shows a sleepable BPF LSM program that looks up a
ruleset, applies it during exec credential preparation, and releases the
lookup reference.

.. code-block:: c

   struct {
           __uint(type, BPF_MAP_TYPE_LANDLOCK_RULESET);
           __uint(max_entries, 1);
           __type(key, __u32);
           __type(value, __u32);
   } ruleset_map SEC(".maps");

   SEC("lsm.s/bprm_creds_for_exec")
   int BPF_PROG(apply_ruleset, struct linux_binprm *bprm)
   {
           const struct bpf_landlock_ruleset *ruleset;
           __u32 key = 0;

           ruleset = bpf_map_lookup_elem(&ruleset_map, &key);
           if (!ruleset)
                   return 0;

           bpf_landlock_restrict_binprm(
                   bprm, ruleset, LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS_EXECTIME);
           bpf_landlock_put_ruleset(ruleset);
           return 0;
   }

Userspace
---------

The following snippet shows how to insert a previously created Landlock
ruleset into the map.

.. code-block:: c

   int populate_ruleset_map(int map_fd, int ruleset_fd)
   {
           __u32 key = 0;
           __u32 value = ruleset_fd;

           return bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
   }

Semantics
=========

- Map creation requires ``CONFIG_SECURITY_LANDLOCK``.  Otherwise,
  ``BPF_MAP_CREATE`` for this type fails with ``-EOPNOTSUPP``.
- Map definitions use ``sizeof(__u32)`` for both keys and values because
  userspace writes ruleset file descriptors into the map.
- From BPF, only ``bpf_map_lookup_elem()`` and ``bpf_map_delete_elem()`` are
  supported for this map type.
- From userspace, insertion is done with ``bpf_map_update_elem()`` using a
  Landlock ruleset FD.
- The looked-up value is an opaque, trusted BTF object reference, so BPF must
  treat it as a handle and release it with ``bpf_landlock_put_ruleset()``.
- ``LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS_EXECTIME`` on the BPF path pins the
  resulting task with ``no_new_privs`` after exec is committed.  When this flag
  is specified, this does not change whether the current exec transition is
  allowed to escalate privileges. (i.e if the execution is a setuid binary)
- ``LANDLOCK_RESTRICT_SELF_EXECTIME`` is rejected on the BPF path because
   ``bpf_landlock_restrict_binprm()`` already defers ruleset enforcement to exec
   point-of-no-return.
- If Landlock support is disabled in the running kernel, programs using the
  associated Landlock kfuncs may still load, but the kfunc call returns
  ``-EOPNOTSUPP`` at runtime.

See ``tools/testing/selftests/bpf/progs/landlock_kfuncs.c`` for a complete
example.
