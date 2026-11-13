.. SPDX-License-Identifier: GPL-2.0-only
.. Copyright (C) 2022 Red Hat, Inc.

=======================
BPF_MAP_TYPE_SK_STORAGE
=======================

.. note::
   - ``BPF_MAP_TYPE_SK_STORAGE`` was introduced in kernel version 5.2

``BPF_MAP_TYPE_SK_STORAGE`` is used to provide socket-local storage for BPF
programs. A map of type ``BPF_MAP_TYPE_SK_STORAGE`` declares the type of storage
to be provided and acts as the handle for accessing the socket-local
storage. The values for maps of type ``BPF_MAP_TYPE_SK_STORAGE`` are stored
locally with each socket instead of with the map. The kernel is responsible for
allocating storage for a socket when requested and for freeing the storage when
either the map or the socket is deleted. Values of a ``BPF_F_INLINE_VALUE`` map
that are in the inline area are freed only with the socket. A value in a normal
element is freed as for other maps (see `Inline values`_).

.. note::
  - The key type must be ``int`` and ``max_entries`` must be set to ``0``.
  - The ``BPF_F_NO_PREALLOC`` flag must be used when creating a map for
    socket-local storage.

Usage
=====

Kernel BPF
----------

bpf_sk_storage_get()
~~~~~~~~~~~~~~~~~~~~

.. code-block:: c

   void *bpf_sk_storage_get(struct bpf_map *map, void *sk, void *value, u64 flags)

Socket-local storage for ``map`` can be retrieved from socket ``sk`` using the
``bpf_sk_storage_get()`` helper. If the ``BPF_LOCAL_STORAGE_GET_F_CREATE``
flag is used then ``bpf_sk_storage_get()`` will create the storage for ``sk``
if it does not already exist. ``value`` can be used together with
``BPF_LOCAL_STORAGE_GET_F_CREATE`` to initialize the storage value, otherwise
it will be zero initialized. Returns a pointer to the storage on success, or
``NULL`` in case of failure.

.. note::
   - ``sk`` is a kernel ``struct sock`` pointer for LSM or tracing programs.
   - ``sk`` is a ``struct bpf_sock`` pointer for other program types.

bpf_sk_storage_delete()
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c

   long bpf_sk_storage_delete(struct bpf_map *map, void *sk)

Socket-local storage for ``map`` can be deleted from socket ``sk`` using the
``bpf_sk_storage_delete()`` helper. Returns ``0`` on success, or negative
error in case of failure.

User space
----------

bpf_map_update_elem()
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c

   int bpf_map_update_elem(int map_fd, const void *key, const void *value, __u64 flags)

Socket-local storage for map ``map_fd`` can be added or updated locally to a
socket using the ``bpf_map_update_elem()`` libbpf function. The socket is
identified by a `socket` ``fd`` stored in the pointer ``key``. The pointer
``value`` has the data to be added or updated to the socket ``fd``. The type
and size of ``value`` should be the same as the value type of the map
definition.

The ``flags`` parameter can be used to control the update behaviour:

- ``BPF_ANY`` will create storage for `socket` ``fd`` or update existing storage.
- ``BPF_NOEXIST`` will create storage for `socket` ``fd`` only if it did not
  already exist, otherwise the call will fail with ``-EEXIST``.
- ``BPF_EXIST`` will update existing storage for `socket` ``fd`` if it already
  exists, otherwise the call will fail with ``-ENOENT``.

Returns ``0`` on success, or negative error in case of failure.

bpf_map_lookup_elem()
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c

   int bpf_map_lookup_elem(int map_fd, const void *key, void *value)

Socket-local storage for map ``map_fd`` can be retrieved from a socket using
the ``bpf_map_lookup_elem()`` libbpf function. The storage is retrieved from
the socket identified by a `socket` ``fd`` stored in the pointer
``key``. Returns ``0`` on success, or negative error in case of failure.

bpf_map_delete_elem()
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c

   int bpf_map_delete_elem(int map_fd, const void *key)

Socket-local storage for map ``map_fd`` can be deleted from a socket using the
``bpf_map_delete_elem()`` libbpf function. The storage is deleted from the
socket identified by a `socket` ``fd`` stored in the pointer ``key``. Returns
``0`` on success, or negative error in case of failure.

Inline values
=============

A map created with ``BPF_F_INLINE_VALUE`` keeps its value in the storage object
of the socket, not in a separate element, so a lookup has one dependent load
less. The flag also works for ``BPF_MAP_TYPE_TASK_STORAGE``,
``BPF_MAP_TYPE_INODE_STORAGE`` and ``BPF_MAP_TYPE_CGRP_STORAGE``. Inline maps
work only on 64-bit kernels.

All inline maps of one owner type share an inline area at the end of each
storage object. A storage object with an inline area is at most 1 KB, including
``struct bpf_local_storage``. On x86-64, the inline area is 840 bytes and the
largest inline value is 832 bytes, because each value has an 8 byte tag. An
owner type can have at most 16 inline maps. These limits can change between
kernel versions.

- Map create fails with ``-EOPNOTSUPP`` on a 32-bit kernel.
- Map create fails with ``-E2BIG`` if the value does not fit even in an empty
  area. It fails with ``-ENOSPC`` only if the area has no room for the value
  now, or if the owner type has 16 inline maps. The application can then
  create the map without the flag.
- The kernel takes the slot early in map create. So ``-ENOSPC`` can come
  before ``-EINVAL`` for special fields or bad BTF, and before the LSM check.
  A create that fails after that holds a slot for a short time.
- Map create fails with ``-EINVAL`` with ``BPF_F_CLONE``, or if the value has
  a spin lock, a kptr, a refcount or an uptr (task storage). Other special
  fields are refused for all local storage maps. An update with ``BPF_F_LOCK``
  fails with ``-EINVAL``.
- An inline map needs ``CAP_BPF``, as other local storage maps do. A BPF token
  can give it inside a user namespace. The area and the limit of 16 maps are
  shared by the whole host, also with users of a BPF token. One such user can
  take the full area or all 16 maps, and make new storage objects of the owner
  type bigger for all users.
- A syscall update copies the value in place, under the storage lock. A reader
  that takes no lock can see a torn value, as in array maps. Without the flag,
  an update makes a new element, so readers see the whole old or new value.
  ``BPF_F_LOCK`` is not available (see above).
- A delete keeps the value bytes. A value pointer that a program keeps after an
  update or a delete stays valid and points to the same slot. It sees, and can
  change, the next value of the same map. Without the flag, it sees the old
  value.
- After map free, old objects keep the tag and value bytes. Each new inline map
  gets a new 8 byte tag, so an accidental match with old bytes is unlikely.
- The tag is predictable. A user that can create inline maps can make another
  map see bytes that it never wrote, in objects made before that map. Tags
  come back after 2^32 inline maps of the owner type: a new map can then see
  old values of a freed map. Both cases are memory safe.
- Only the size of an object decides if it holds the slot of a map. The size is
  set when the object is made. An object without room keeps the value in a
  normal element. Programs must not depend on which one applies.
- The slot of a map comes back after the map is freed, which can be later than
  ``close()``. For a short time, a new map create can then fail with
  ``-ENOSPC``.
- In map-in-map, inline and normal inner maps are not interchangeable: the map
  flags must match. The kernel's copy of the inner map template holds no
  slot, but the map given as ``inner_map_fd`` holds one until it is freed.
  This is also true for the template map that libbpf makes.
- The sk storage map iterator fails with ``-EOPNOTSUPP`` for an inline map.
  sk diag shows inline values, also in a dump of all maps.
- As for all local storage maps, a delete in NMI context fails with
  ``-EOPNOTSUPP``. In tracing programs, the sk storage helpers refuse hard IRQ
  and NMI context: ``bpf_sk_storage_get()`` returns NULL and
  ``bpf_sk_storage_delete()`` returns ``-EPERM``.

Inline maps also change things for users of normal maps:

- A lookup of a normal map costs a little more, also when no inline map
  exists: it tests if the map has an inline slot.
- While an inline map exists, every new storage object of that owner type gets
  the inline area, also for owners that use only normal maps. The memcg of the
  map that makes an object pays for all of it. For sockets, the object counts
  in ``sk_omem_alloc``, so ``optmem_max`` is reached sooner.
- An object with an inline area is freed only when its owner goes away (the
  socket is closed and freed, the task struct is freed, the cgroup is freed or
  the inode is evicted), after an RCU tasks trace grace period. Until then it
  stays charged, also after all its values are deleted and all inline maps are
  freed.

A new version of an inline map that is created while the old one exists gets a
different slot. It can be after the old one, and then new objects become bigger.
To keep one slot across restarts of an application, pin the map and reuse it
with ``bpf_map__reuse_fd()``.

A libbpf skeleton cannot run ``bpf_object__load()`` again after a failure. To
fall back:

1. Open the skeleton, add ``BPF_F_INLINE_VALUE`` to the map flags, and load
   it. ``bpf_map__set_map_flags()`` replaces all flags, so keep the others::

     bpf_map__set_map_flags(map, bpf_map__map_flags(map) | BPF_F_INLINE_VALUE);

2. If the load fails with ``-ENOSPC``, ``-E2BIG``, ``-EOPNOTSUPP``, or
   ``-EINVAL`` (a kernel without the flag), destroy the skeleton, open it
   again, and load it without the flag. A kernel with the flag also gives
   ``-EINVAL`` for the cases above that inline maps do not allow.

A map with ``LIBBPF_PIN_BY_NAME`` does not mix with this fallback: libbpf
reuses a pinned map only if its ``map_flags`` match the map definition.

Examples
========

Kernel BPF
----------

This snippet shows how to declare socket-local storage in a BPF program:

.. code-block:: c

    struct {
            __uint(type, BPF_MAP_TYPE_SK_STORAGE);
            __uint(map_flags, BPF_F_NO_PREALLOC);
            __type(key, int);
            __type(value, struct my_storage);
    } socket_storage SEC(".maps");

This snippet shows how to retrieve socket-local storage in a BPF program:

.. code-block:: c

    SEC("sockops")
    int _sockops(struct bpf_sock_ops *ctx)
    {
            struct my_storage *storage;
            struct bpf_sock *sk;

            sk = ctx->sk;
            if (!sk)
                    return 1;

            storage = bpf_sk_storage_get(&socket_storage, sk, 0,
                                         BPF_LOCAL_STORAGE_GET_F_CREATE);
            if (!storage)
                    return 1;

            /* Use 'storage' here */

            return 1;
    }


Please see the ``tools/testing/selftests/bpf`` directory for functional
examples.

References
==========

https://lwn.net/ml/netdev/20190426171103.61892-1-kafai@fb.com/
