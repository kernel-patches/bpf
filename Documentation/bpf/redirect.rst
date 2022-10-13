.. SPDX-License-Identifier: GPL-2.0-only
.. Copyright (C) 2022 Red Hat, Inc.

============
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
inside a single NAPI poll sequence.

.. note::
    Not all drivers support transmitting frames after a redirect, and for
    those that do, not all of them support non-linear frames. Non-linear xdp
    bufs/frames are bufs/frames that contain more than one fragment.

XDP_REDIRECT works with the following map types:

- BPF_MAP_TYPE_DEVMAP
- BPF_MAP_TYPE_DEVMAP_HASH
- BPF_MAP_TYPE_CPUMAP
- BPF_MAP_TYPE_XSKMAP

For more information on these maps, please see the specific map documentation.

References
===========

- https://elixir.bootlin.com/linux/latest/source/net/core/filter.c#L4106
