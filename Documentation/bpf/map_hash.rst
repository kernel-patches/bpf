.. SPDX-License-Identifier: GPL-2.0-only
.. Copyright (C) 2022 Red Hat, Inc.
.. Copyright (C) 2022 Isovalent, Inc.

===============================================
BPF_MAP_TYPE_HASH, with PERCPU and LRU Variants
===============================================

.. note::
   - ``BPF_MAP_TYPE_HASH`` was introduced in kernel version 3.19
   - ``BPF_MAP_TYPE_PERCPU_HASH`` was introduced in version 4.6
   - Both ``BPF_MAP_TYPE_LRU_HASH`` and ``BPF_MAP_TYPE_LRU_PERCPU_HASH``
     were introduced in version 4.10

``BPF_MAP_TYPE_HASH`` and ``BPF_MAP_TYPE_PERCPU_HASH`` provide general
purpose hash map storage. Both the key and the value can be structs,
allowing for composite keys and values.

The kernel is responsible for allocating and freeing key/value pairs, up
to the max_entries limit that you specify. Hash maps use pre-allocation
of hash table elements by default. The ``BPF_F_NO_PREALLOC`` flag can be
used to disable pre-allocation when it is too memory expensive.

``BPF_MAP_TYPE_PERCPU_HASH`` provides a separate value slot per
CPU. The per-cpu values are stored internally in an array.

The ``BPF_MAP_TYPE_LRU_HASH`` and ``BPF_MAP_TYPE_LRU_PERCPU_HASH``
variants add LRU semantics to their respective hash tables. An LRU hash
will automatically evict the least recently used entries when the hash
table reaches capacity. An LRU hash maintains an internal LRU list that
is used to select elements for eviction. This internal LRU list is
shared across CPUs but it is possible to request a per CPU LRU list with
the ``BPF_F_NO_COMMON_LRU`` flag when calling ``bpf_map_create``.

Usage
=====

.. c:function::
   long bpf_map_update_elem(struct bpf_map *map, const void *key, const void *value, u64 flags)

Hash entries can be added or updated using the ``bpf_map_update_elem()``
helper. This helper replaces existing elements atomically. The ``flags``
parameter can be used to control the update behaviour:

- ``BPF_ANY`` will create a new element or update an existing element
- ``BPF_NOEXIST`` will create a new element only if one did not already
  exist
- ``BPF_EXIST`` will update an existing element

``bpf_map_update_elem()`` returns 0 on success, or negative error in
case of failure.

.. c:function::
   void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)

Hash entries can be retrieved using the ``bpf_map_lookup_elem()``
helper. This helper returns a pointer to the value associated with
``key``, or ``NULL`` if no entry was found.

.. c:function::
   long bpf_map_delete_elem(struct bpf_map *map, const void *key)

Hash entries can be deleted using the ``bpf_map_delete_elem()``
helper. This helper will return 0 on success, or negative error in case
of failure.

Per CPU Hashes
--------------

For ``BPF_MAP_TYPE_PERCPU_HASH`` and ``BPF_MAP_TYPE_LRU_PERCPU_HASH``
the ``bpf_map_update_elem()`` and ``bpf_map_lookup_elem()`` helpers
automatically access the hash slot for the current CPU.

.. c:function::
   void *bpf_map_lookup_percpu_elem(struct bpf_map *map, const void *key, u32 cpu)

The ``bpf_map_lookup_percpu_elem()`` helper can be used to lookup the
value in the hash slot for a specific CPU. Returns value associated with
``key`` on ``cpu`` , or ``NULL`` if no entry was found or ``cpu`` is
invalid.

Concurrency
-----------

Values stored in ``BPF_MAP_TYPE_HASH`` can be accessed concurrently by
programs running on different CPUs.  Since Kernel version 5.1, the BPF
infrastructure provides ``struct bpf_spin_lock`` to synchronise access.
See ``tools/testing/selftests/bpf/progs/test_spin_lock.c``.

Userspace
---------

.. c:function::
   int bpf_map_get_next_key(int fd, const void *cur_key, void *next_key)

In userspace, it is possible to iterate through the keys of a hash using
libbpf's ``bpf_map_get_next_key()`` function. The first key can be fetched by
calling ``bpf_map_get_next_key()`` with ``cur_key`` set to
``NULL``. Subsequent calls will fetch the next key that follows the
current key. ``bpf_map_get_next_key()`` returns 0 on success, -ENOENT if
cur_key is the last key in the hash, or negative error in case of
failure.

Note that if ``cur_key`` gets deleted then ``bpf_map_get_next_key()``
will instead return the *first* key in the hash table which is
undesirable. It is recommended to use batched lookup if there is going
to be key deletion intermixed with ``bpf_map_get_next_key()``.

Examples
========

Please see the ``tools/testing/selftests/bpf`` directory for functional
examples.  The code snippets below demonstrates API usage.

This example shows how to declare an LRU Hash with a struct key and a
struct value.

.. code-block:: c

    #include <linux/bpf.h>
    #include <bpf/bpf_helpers.h>

    struct key {
        __u32 srcip;
    };

    struct value {
        __u64 packets;
        __u64 bytes;
    };

    struct {
            __uint(type, BPF_MAP_TYPE_LRU_HASH);
            __uint(max_entries, 32);
            __type(key, struct key);
            __type(value, struct value);
    } packet_stats SEC(".maps");

This example shows how to create or update hash values using atomic
instructions:

.. code-block:: c

    static void update_stats(__u32 srcip, int bytes)
    {
            struct key key = {
                    .srcip = srcip,
            };
            struct value *value = bpf_map_lookup_elem(&packet_stats, &key);

            if (value) {
                    __sync_fetch_and_add(&value->packets, 1);
                    __sync_fetch_and_add(&value->bytes, bytes);
            } else {
                    struct value newval = { 1, bytes };

                    bpf_map_update_elem(&packet_stats, &key, &newval, BPF_NOEXIST);
            }
    }

Userspace walking the map elements from the map declared above:

.. code-block:: c

    #include <bpf/libbpf.h>
    #include <bpf/bpf.h>

    static void walk_hash_elements(int map_fd)
    {
            struct key *cur_key = NULL;
            struct key next_key;
            struct value value;
            int err;

            for (;;) {
                    err = bpf_map_get_next_key(map_fd, cur_key, &next_key);
                    if (err)
                            break;

                    bpf_map_lookup_elem(map_fd, &next_key, &value);

                    // Use key and value here

                    cur_key = &next_key;
            }
    }

Internals
=========

This section of the document is targeted at Linux developers and describes
aspects of the map implementations that are not considered stable ABI. The
following details are subject to change in future versions of the kernel.

``BPF_MAP_TYPE_LRU_HASH`` and variants
--------------------------------------

An LRU hashmap type consists of two properties: Firstly, it is a hash map and
hence is indexable by key for constant time lookups. Secondly, when at map
capacity, map updates will trigger eviction of old entries based on the age of
the elements in a set of lists. Each of these properties may be either global
or per-CPU, depending on the map type and flags used to create the map:

.. flat-table:: Comparison of map properties by map type (x-axis) and flags
   (y-axis)

   * -
     - ``BPF_MAP_TYPE_LRU_HASH``
     - ``BPF_MAP_TYPE_LRU_PERCPU_HASH``

   * - ``BPF_NO_COMMON_LRU``
     - Per-CPU LRU, global map
     - Per-CPU LRU, per-cpu map

   * - ``!BPF_NO_COMMON_LRU``
     - Global LRU, global map
     - Global LRU, per-cpu map

The commit message for LRU map support provides a general overview of the
underlying LRU algorithm used for entry eviction when the table is full:

::

    commit 3a08c2fd763450a927d1130de078d6f9e74944fb
    Author: Martin KaFai Lau <kafai@fb.com>
    Date:   Fri Nov 11 10:55:06 2016 -0800

        bpf: LRU List

        Introduce bpf_lru_list which will provide LRU capability to
        the bpf_htab in the later patch.

        * General Thoughts:
        1. Target use case.  Read is more often than update.
           (i.e. bpf_lookup_elem() is more often than bpf_update_elem()).
           If bpf_prog does a bpf_lookup_elem() first and then an in-place
           update, it still counts as a read operation to the LRU list concern.
        2. It may be useful to think of it as a LRU cache
        3. Optimize the read case
           3.1 No lock in read case
           3.2 The LRU maintenance is only done during bpf_update_elem()
        4. If there is a percpu LRU list, it will lose the system-wise LRU
           property.  A completely isolated percpu LRU list has the best
           performance but the memory utilization is not ideal considering
           the work load may be imbalance.
        5. Hence, this patch starts the LRU implementation with a global LRU
           list with batched operations before accessing the global LRU list.
           As a LRU cache, #read >> #update/#insert operations, it will work well.
        6. There is a local list (for each cpu) which is named
           'struct bpf_lru_locallist'.  This local list is not used to sort
           the LRU property.  Instead, the local list is to batch enough
           operations before acquiring the lock of the global LRU list.  More
           details on this later.
        7. In the later patch, it allows a percpu LRU list by specifying a
           map-attribute for scalability reason and for use cases that need to
           prepare for the worst (and pathological) case like DoS attack.
           The percpu LRU list is completely isolated from each other and the
           LRU nodes (including free nodes) cannot be moved across the list.  The
           following description is for the global LRU list but mostly applicable
           to the percpu LRU list also.

        * Global LRU List:
        1. It has three sub-lists: active-list, inactive-list and free-list.
        2. The two list idea, active and inactive, is borrowed from the
           page cache.
        3. All nodes are pre-allocated and all sit at the free-list (of the
           global LRU list) at the beginning.  The pre-allocation reasoning
           is similar to the existing BPF_MAP_TYPE_HASH.  However,
           opting-out prealloc (BPF_F_NO_PREALLOC) is not supported in
           the LRU map.

        * Active/Inactive List (of the global LRU list):
        1. The active list, as its name says it, maintains the active set of
           the nodes.  We can think of it as the working set or more frequently
           accessed nodes.  The access frequency is approximated by a ref-bit.
           The ref-bit is set during the bpf_lookup_elem().
        2. The inactive list, as its name also says it, maintains a less
           active set of nodes.  They are the candidates to be removed
           from the bpf_htab when we are running out of free nodes.
        3. The ordering of these two lists is acting as a rough clock.
           The tail of the inactive list is the older nodes and
           should be released first if the bpf_htab needs free element.

        * Rotating the Active/Inactive List (of the global LRU list):
        1. It is the basic operation to maintain the LRU property of
           the global list.
        2. The active list is only rotated when the inactive list is running
           low.  This idea is similar to the current page cache.
           Inactive running low is currently defined as
           "# of inactive < # of active".
        3. The active list rotation always starts from the tail.  It moves
           node without ref-bit set to the head of the inactive list.
           It moves node with ref-bit set back to the head of the active
           list and then clears its ref-bit.
        4. The inactive rotation is pretty simply.
           It walks the inactive list and moves the nodes back to the head of
           active list if its ref-bit is set. The ref-bit is cleared after moving
           to the active list.
           If the node does not have ref-bit set, it just leave it as it is
           because it is already in the inactive list.

        * Shrinking the Inactive List (of the global LRU list):
        1. Shrinking is the operation to get free nodes when the bpf_htab is
           full.
        2. It usually only shrinks the inactive list to get free nodes.
        3. During shrinking, it will walk the inactive list from the tail,
           delete the nodes without ref-bit set from bpf_htab.
        4. If no free node found after step (3), it will forcefully get
           one node from the tail of inactive or active list.  Forcefully is
           in the sense that it ignores the ref-bit.

        * Local List:
        1. Each CPU has a 'struct bpf_lru_locallist'.  The purpose is to
           batch enough operations before acquiring the lock of the
           global LRU.
        2. A local list has two sub-lists, free-list and pending-list.
        3. During bpf_update_elem(), it will try to get from the free-list
           of (the current CPU local list).
        4. If the local free-list is empty, it will acquire from the
           global LRU list.  The global LRU list can either satisfy it
           by its global free-list or by shrinking the global inactive
           list.  Since we have acquired the global LRU list lock,
           it will try to get at most LOCAL_FREE_TARGET elements
           to the local free list.
        5. When a new element is added to the bpf_htab, it will
           first sit at the pending-list (of the local list) first.
           The pending-list will be flushed to the global LRU list
           when it needs to acquire free nodes from the global list
           next time.

        * Lock Consideration:
        The LRU list has a lock (lru_lock).  Each bucket of htab has a
        lock (buck_lock).  If both locks need to be acquired together,
        the lock order is always lru_lock -> buck_lock and this only
        happens in the bpf_lru_list.c logic.

        In hashtab.c, both locks are not acquired together (i.e. one
        lock is always released first before acquiring another lock).

        Signed-off-by: Martin KaFai Lau <kafai@fb.com>
        Acked-by: Alexei Starovoitov <ast@kernel.org>
        Signed-off-by: David S. Miller <davem@davemloft.net>

Notably, there are various steps that the update algorithm attempts in order to
enforce the LRU property which have increasing impacts on other CPUs involved
in the operations:

- Attempt to use CPU-local state to batch operations
- Attempt to fetch free nodes from global lists
- Attempt to pull any node from a global list and remove it from the hashmap
- Attempt to pull any node from any CPU's list and remove it from the hashmap

Even if an LRU node may be acquired, maps of type ``BPF_MAP_TYPE_LRU_HASH``
may fail to insert the entry into the map if other CPUs are heavily contending
on the global hashmap lock.

This algorithm is described visually in the following diagram:

.. kernel-figure::  map_lru_hash_update.dot
   :alt:    Diagram outlining the LRU eviction steps taken during map update

   LRU hash eviction during map update for ``BPF_MAP_TYPE_LRU_HASH`` and
   variants

Map updates start from the oval in the top right "begin ``bpf_map_update()``"
and progress through the graph towards the bottom where the result may be
either a successful update or a failure with various error codes. The key in
the top right provides indicators for which locks may be involved in specific
operations. This is intended as a visual hint for reasoning about how map
contention may impact update operations, though the map type and flags may
impact the actual contention on those locks, based on the logic described in
the table above. For instance, if the map is created with type
``BPF_MAP_TYPE_LRU_PERCPU_HASH`` and flags ``BPF_NO_COMMON_LRU`` then all map
properties would be per-cpu.

The dot file source for the above diagram is uses internal kernel function
names for the node names in order to make the corresponding logic easier to
find. See ``Documentation/bpf/map_lru_hash_update.dot`` for more details.
