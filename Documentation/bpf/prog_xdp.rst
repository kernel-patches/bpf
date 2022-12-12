.. SPDX-License-Identifier: GPL-2.0-only
.. Copyright (C) 2022 Red Hat, Inc.

================
XDP BPF Programs
================

XDP (eXpress Data Path) is a fast path in the kernel network stack. XDP allows
for packet processing by BPF programs before the packets traverse the L4-L7
network stack. Programs of type ``BPF_PROG_TYPE_XDP`` are attached to the XDP
hook of a specific interface in one of three modes:

- ``SKB_MODE`` - The hook point is in the generic net device
- ``DRV_MODE`` - The hook point is in the driver for the interface
- ``HW_MODE`` - The BPF program is offloaded to the NIC

The BPF program attached to an interface's XDP hook gets called for each L2
frame that is received on the interface. The program is passed a ``struct xdp_md
*ctx`` which gives access to the L2 data frame as well as some essential
metadata for the frame:

.. code-block:: c

    struct xdp_md {
            __u32 data;
            __u32 data_end;
            __u32 data_meta;

            __u32 ingress_ifindex; /* rxq->dev->ifindex */
            __u32 rx_queue_index;  /* rxq->queue_index  */
            __u32 egress_ifindex;  /* txq->dev->ifindex */
    };

The BPF program can read and modify the frame before deciding what action should
be taken for the packet. The program returns one of the following action values
in order to tell the driver or net device how to process the packet (details in
:ref:`xdp_packet_actions`):

- ``XDP_DROP`` - Drop the packet without any further processing
- ``XDP_PASS`` - Pass the packet to the kernel network stack for further
  processing
- ``XDP_TX`` - Transmit the packet out of the same interface
- ``XDP_REDIRECT`` - Redirect the packet to a specific destination
- ``XDP_ABORTED`` - Drop the packet and notify an exception state

There are many BPF helper functions available to XDP programs for accessing and
modifying packet data, for interacting with the kernel networking stack and for
using BPF maps. `bpf-helpers(7)`_ describes the helpers available to XDP
programs.

The `libxdp`_ library provides functions for attaching XDP programs to network
interfaces and for using ``AF_XDP`` sockets.

XDP Modes
=========

SKB Mode
--------

An XDP program attached in SKB mode gets executed by the kernel network stack
*after* the driver has created a ``struct sk_buff`` (SKB) and passed it to the
networking stack. SKB mode is also referred to as *generic* mode and is always
available, whether or not the driver is XDP-enabled. An XDP program in SKB mode
is run by the netdev before classifiers or ``tc`` BPF programs are run.

Driver Mode
-----------

An XDP program attached in driver mode gets executed by the network driver for
an interface *before* the driver creates a ``struct sk_buff`` (SKB) for the
incoming packet. The XDP program runs immediately after the driver receives the
packet. This gives the XDP program an opportunity to entirely avoid the cost of
SKB creation and kernel network stack processing.

Driver mode requires the driver to be XDP-enabled so is not always available.

Hardware Mode
-------------

Some devices may support hardware offload of BPF programs, which they do in a
hardware specific way.

.. _xdp_packet_actions:

XDP Packet Actions
==================

XDP_DROP
--------

The ``XDP_DROP`` action tells the driver or netdev to drop the XDP frame without
any further processing.

XDP_PASS
--------

The ``XDP_PASS`` action tells the driver to convert the XDP frame into an SKB
and the driver or netdev to pass the SKB on to the kernel network stack for
normal processing.

XDP_TX
------

The ``XDP_TX`` action tells the driver or netdev to transmit the XDP frame out
of the associated interface.

XDP_REDIRECT
------------

The ``XDP_REDIRECT`` action tells the driver to redirect the packet for further
processing. There are several types of redirect available to the XDP program:

- Redirect to another device by ifindex
- Redirect to another device using a devmap
- Redirect into an ``AF_XDP`` socket using an xskmap
- Redirect to another CPU using a cpumap, before delivering to the network stack

The ``bpf_redirect()`` and ``bpf_redirect_map()`` helper functions are used
to set up the desired redirect destination before returning ``XDP_REDIRECT`` to
the driver.

.. code-block:: c

    long bpf_redirect(u32 ifindex, u64 flags)

The ``bpf_redirect()`` helper function redirects the packet to the net device
identified by ``ifindex``.

.. code-block:: c

    long bpf_redirect_map(struct bpf_map *map, u32 key, u64 flags)

The ``bpf_redirect_map()`` helper function redirects the packet to the
destination referenced by ``map`` at index ``key``. The type of destination
depends on the type ``map`` that is used:

- ``BPF_MAP_TYPE_DEVMAP`` and ``BPF_MAP_TYPE_DEVMAP_HASH`` redirects the packet
  to another net device
- ``BPF_MAP_TYPE_CPUMAP`` redirects the packet processing to a specific CPU
- ``BPF_MAP_TYPE_XSKMAP`` redirects the packet to an ``AF_XDP`` socket. See
  ../networking/af_xdp.rst for more information.

Detailed behaviour of ``bpf_redirect()`` and ``bpf_redirect_map()`` is described
in `bpf-helpers(7)`_. ``XDP_REDIRECT`` is described in more detail in
redirect.rst.

XDP_ABORTED
-----------

The ``XDP_ABORTED`` action tells the driver that the BPF program exited in an
exception state. The driver will drop the packet in the same way as if the BPF
program returned ``XDP_DROP`` but the ``trace_xdp_exception`` trace point is also
triggered.

Examples
========

An example XDP program that uses ``XDP_REDIRECT`` can be found in
`tools/testing/selftests/bpf/progs/xdp_redirect_multi_kern.c`_ and the
corresponding user space code in
`tools/testing/selftests/bpf/xdp_redirect_multi.c`_

References
==========

- https://github.com/xdp-project/xdp-tools
- https://github.com/xdp-project/xdp-tutorial
- https://docs.cilium.io/en/latest/bpf/progtypes

.. Links
.. _bpf-helpers(7): https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
.. _libxdp: https://github.com/xdp-project/xdp-tools/tree/master/lib/libxdp
.. _tools/testing/selftests/bpf/progs/xdp_redirect_multi_kern.c:
   https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/tools/testing/selftests/bpf/progs/xdp_redirect_multi_kern.c
.. _tools/testing/selftests/bpf/xdp_redirect_multi.c:
   https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/tools/testing/selftests/bpf/xdp_redirect_multi.c
