.. SPDX-License-Identifier: GPL-2.0-only
.. Copyright (C) 2022 Red Hat, Inc.

=================================================
BPF_MAP_TYPE_DEVMAP and BPF_MAP_TYPE_DEVMAP_HASH
=================================================

.. note::
   - ``BPF_MAP_TYPE_DEVMAP`` was introduced in kernel version 4.14
   - ``BPF_MAP_TYPE_DEVMAP_HASH`` was introduced in kernel version 5.4

``BPF_MAP_TYPE_DEVMAP`` is a BPF map, primarily used as a backend map for the XDP
BPF helper call ``bpf_redirect_map()``. It's backed by an array that uses the key as
the index to lookup a reference to a net device. The user provides <``key``/ ``ifindex``>
pairs to update the map with new net devices.

``BPF_MAP_TYPE_DEVMAP_HASH`` is also a backend map for ``bpf_redirect_map()``.
It's backed by a hash table that uses the ``ifindex`` as the key to lookup a reference
to a net device. As it's a hash map, it allows for densely packing the net devices
(compared with the sparsely packed ``BPF_MAP_TYPE_DEVMAP``). The user provides
<``key``/ ``struct bpf_devmap_val``> pairs to update the map with new net devices.

The setup and packet enqueue/send code is shared between the two types of
devmap; only the lookup and insertion is different.

XDP_REDIRECT
============

XDP_REDIRECT works by a three-step process, implemented as follows:

1. The ``bpf_redirect()`` and ``bpf_redirect_map()`` helpers will lookup the
   target of the redirect and store it (along with some other metadata) in a
   per-CPU ``struct bpf_redirect_info``. This is where the maps above come into
   play.

2. When the program returns the ``XDP_REDIRECT`` return code, the driver will
   call ``xdp_do_redirect()`` which will use the information in ``struct
   bpf_redirect_info`` to actually enqueue the frame into a map type-specific
   bulk queue structure.

3. Before exiting its NAPI poll loop, the driver will call ``xdp_do_flush()``,
   which will flush all the different bulk queues, thus completing the
   redirect.

Pointers to the map entries will be kept around for this whole sequence of
steps, protected by RCU. However, there is no top-level ``rcu_read_lock()`` in
the core code; instead, the RCU protection relies on everything happening
inside a single NAPI poll sequence, which means it's between a pair of calls
to ``local_bh_disable()`` / ``local_bh_enable()``.

The map entries are marked as ``__rcu`` and the map code makes sure to dereference
those pointers with ``rcu_dereference_check()`` in a way that works for both
sections that to hold an ``rcu_read_lock()`` and sections that are called from
NAPI without a separate ``rcu_read_lock()``. The code below does not use RCU
annotations, but relies on those in the map code.

.. note::
    ``XDP_REDIRECT`` is not fully supported yet for xdp frags since not all XDP
    capable drivers can map a non-linear ``xdp_frame`` in ``ndo_xdp_xmit``.

Usage
=====

.. c:function::
   long bpf_map_update_elem(struct bpf_map *map, const void *key, const void *value, u64 flags)

 Net device entries can be added or updated using the ``bpf_map_update_elem()``
 helper. This helper replaces existing elements atomically. The ``flags``
 parameter can be used to control the update behaviour:

 - ``BPF_ANY`` will create a new element or update an existing element
 - ``BPF_NOEXIST`` will create a new element only if one did not already
   exist
 - ``BPF_EXIST`` will update an existing element

 ``bpf_map_update_elem()`` returns 0 on success, or negative error in
 case of failure.

 The value parameter is of type ``struct bpf_devmap_val``:

 .. code-block:: c

    struct bpf_devmap_val {
        __u32 ifindex;   /* device index */
        union {
            int   fd;  /* prog fd on map write */
            __u32 id;  /* prog id on map read */
        } bpf_prog;
    };

 DEVMAPs can associate a program with a device entry by adding a ``bpf_prog.fd``
 to ``struct bpf_devmap_val``. Programs are run after ``XDP_REDIRECT`` and have
 access to both Rx device and Tx device. The  program associated with the ``fd``
 must have type XDP with expected attach type ``xdp_devmap``.
 When a program is associated with a device index, the program is run on an
 ``XDP_REDIRECT`` and before the buffer is added to the per-cpu queue. Examples
 of how to attach/use xdp_devmap progs can be found in the kernel selftests:

 - test_xdp_with_devmap_helpers_
 - xdp_devmap_attach_

.. _xdp_devmap_attach: https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/prog_tests/xdp_devmap_attach.c
.. _test_xdp_with_devmap_helpers: https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/test_xdp_with_devmap_helpers.c

.. c:function::
   void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)

 net device entries can be retrieved using the ``bpf_map_lookup_elem()``
 helper. This helper returns a pointer to the value associated with ``key``, or
 ``NULL`` if no entry was found.

.. c:function::
   long bpf_map_delete_elem(struct bpf_map *map, const void *key)

 net device entries can be deleted using the ``bpf_map_delete_elem()``
 helper. This helper will return 0 on success, or negative error in case of
 failure.

.. c:function::
     long bpf_redirect_map(struct bpf_map *map, u32 key, u64 flags)

 Redirect the packet to the endpoint referenced by map at index ``key``.
 For ``BPF_MAP_TYPE_DEVMAP`` and ``BPF_MAP_TYPE_DEVMAP_HASH`` this map contains
 references to net devices (for forwarding packets through other ports).

 The lower two bits of *flags* are used as the return code if the map lookup
 fails. This is so that the return value can be one of the XDP program return
 codes up to ``XDP_TX``, as chosen by the caller. The higher bits of ``flags``
 can be set to ``BPF_F_BROADCAST`` or ``BPF_F_EXCLUDE_INGRESS`` as defined
 below.

 With ``BPF_F_BROADCAST`` the packet will be broadcast to all the interfaces
 in the map, with ``BPF_F_EXCLUDE_INGRESS`` the ingress interface will be excluded
 from the broadcast.

 This helper will return ``XDP_REDIRECT`` on success, or the value of the two
 lower bits of the *flags* argument if the map lookup fails.

Examples
========

Kernel BPF
----------

The following code snippet shows how to declare a ``BPF_MAP_TYPE_DEVMAP``
called tx_port.

.. code-block:: c

    struct {
        __uint(type, BPF_MAP_TYPE_DEVMAP);
        __uint(key_size, sizeof(int));
        __uint(value_size, sizeof(int));
        __uint(max_entries, 256);
    } tx_port SEC(".maps");

The following code snippet shows how to declare a ``BPF_MAP_TYPE_DEVMAP_HASH``
called forward_map.

.. code-block:: c

    struct {
        __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
        __uint(key_size, sizeof(int));
        __uint(value_size, sizeof(struct bpf_devmap_val));
        __uint(max_entries, 32);
    } forward_map SEC(".maps");

The following code snippet shows a simple xdp_redirect_map program.

.. code-block:: c

    SEC("xdp")
    int xdp_redirect_map_func(struct xdp_md *ctx)
    {
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        int action = XDP_PASS;
        int index = ctx->ingress_ifindex;

        action = bpf_redirect_map(&tx_port, index, BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS);

    out:
        return action;
    }


User space
----------

The following code snippet shows how to update a devmap called ``tx_port``.

.. code-block:: c

    int update_devmap(int ifindex, int redirect_ifindex)
    {
        int ret = -1;

        ret = bpf_map_update_elem(bpf_map__fd(tx_port), &ifindex, &redirect_ifindex, 0);
        if (ret < 0) {
            fprintf(stderr, "Failed to update devmap_ value: %s\n",
                strerror(errno));
        }

        return ret;
    }

The following code snippet shows how to update a hash_devmap called ``forward_map``.

.. code-block:: c

    int update_devmap(int ifindex, int redirect_ifindex)
    {
        struct bpf_devmap_val devmap_val;
        int ret = -1;

        devmap_val.ifindex = redirect_ifindex;
        ret = bpf_map_update_elem(bpf_map__fd(forward_map), &ifindex, &devmap_val, 0);
        if (ret < 0) {
            fprintf(stderr, "Failed to update devmap_ value: %s\n",
                strerror(errno));
        }
        return ret;
    }

References
===========

- https://lwn.net/Articles/728146/
- https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/commit/?id=6f9d451ab1a33728adb72d7ff66a7b374d665176
- https://elixir.bootlin.com/linux/latest/source/net/core/filter.c#L4106
