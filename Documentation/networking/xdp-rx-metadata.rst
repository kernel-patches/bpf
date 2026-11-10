.. SPDX-License-Identifier: GPL-2.0

===============
XDP RX Metadata
===============

This document describes how an eXpress Data Path (XDP) program can access
hardware metadata related to a packet using a set of helper functions,
and how it can pass that metadata on to other consumers.

General Design
==============

XDP has access to a set of kfuncs to manipulate the metadata in an XDP frame.
Every device driver that wishes to expose additional packet metadata can
implement these kfuncs. The set of kfuncs is declared in ``include/net/xdp.h``
via ``XDP_METADATA_KFUNC_xxx``.

Currently, the following kfuncs are supported. In the future, as more
metadata is supported, this set will grow:

.. kernel-doc:: net/core/xdp.c
   :identifiers: bpf_xdp_metadata_rx_timestamp

.. kernel-doc:: net/core/xdp.c
   :identifiers: bpf_xdp_metadata_rx_hash

.. kernel-doc:: net/core/xdp.c
   :identifiers: bpf_xdp_metadata_rx_vlan_tag

An XDP program can use these kfuncs to read the metadata into stack
variables for its own consumption. Or, to pass the metadata on to other
consumers, an XDP program can store it into the metadata area carried
ahead of the packet. Not all packets will necessary have the requested
metadata available in which case the driver returns ``-ENODATA``.

Not all kfuncs have to be implemented by the device driver; when not
implemented, the default ones that return ``-EOPNOTSUPP`` will be used
to indicate the device driver has not implemented this kfunc.


Within an XDP frame, the metadata layout (accessed via ``xdp_buff``) is
as follows::

  +----------+-----------------+------+
  | headroom | custom metadata | data |
  +----------+-----------------+------+
             ^                 ^
             |                 |
   xdp_buff->data_meta   xdp_buff->data

An XDP program can store individual metadata items into this ``data_meta``
area in whichever format it chooses. Later consumers of the metadata
will have to agree on the format by some out of band contract (like for
the AF_XDP use case, see below).

SKB Core Extension Area
=======================

An XDP program can also store RX metadata that the kernel sets on the
``skb`` built from the packet. It stores and deletes the values with
these kfuncs:

.. kernel-doc:: net/core/xdp.c
   :identifiers: bpf_xdp_skb_ext_store_rx_hash

.. kernel-doc:: net/core/xdp.c
   :identifiers: bpf_xdp_skb_ext_store_rx_vlan

.. kernel-doc:: net/core/xdp.c
   :identifiers: bpf_xdp_skb_ext_store_rx_csum

.. kernel-doc:: net/core/xdp.c
   :identifiers: bpf_xdp_skb_ext_del

The values are kept in the skb core extension area. The area starts at
``data_hard_start + sizeof(struct xdp_frame)``, right after the room for
the ``xdp_frame``::

  +-----------+-----------+----------------+---------------------+------+
  | xdp_frame |  skb core |    headroom    |   custom metadata   | data |
  |           | extension |                |                     |      |
  +-----------+-----------+----------------+---------------------+------+
  ^                                        ^                     ^
  |                                        |                     |
  xdp_buff->data_hard_start       xdp_buff->data_meta     xdp_buff->data

The area is not an skb extension (``struct skb_ext``) and needs no
extra allocation. It takes no space until the first store. It holds a
4-byte header and the stored entries. The header and all three entries
take 20 bytes. ``bpf_xdp_adjust_head``, ``bpf_xdp_adjust_meta`` and
``bpf_xdp_pull_data`` do not move the packet or the metadata into the
area.

The kernel sets the stored values on the ``skb`` in these cases:

- When cpumap or veth builds the ``skb`` from an ``xdp_frame`` after
  ``XDP_REDIRECT``.
- When ``BPF_PROG_RUN`` with ``BPF_F_TEST_XDP_LIVE_FRAMES`` builds the
  ``skb`` after ``XDP_PASS``.
- On ``XDP_PASS``, in a driver with the ``skb-ext-pass`` XDP feature,
  see `Supported Devices`_.

On ``XDP_PASS``, the stored values replace the values that the driver
sets from the RX descriptor. On a native XDP driver without the feature,
the kernel warns once when the program returns ``XDP_PASS`` with stored
values. When XDP runs on an ``skb``, in generic XDP or when veth receives
an ``skb`` from its peer, the kernel does not set the stored values on
``XDP_PASS`` and also warns once.

The program that stores the values can read them back. So can the
programs that run on the ``xdp_frame`` after ``XDP_REDIRECT``, on cpumap,
devmap and veth:

.. kernel-doc:: net/core/xdp.c
   :identifiers: bpf_xdp_skb_ext_load_rx_hash

.. kernel-doc:: net/core/xdp.c
   :identifiers: bpf_xdp_skb_ext_load_rx_vlan

.. kernel-doc:: net/core/xdp.c
   :identifiers: bpf_xdp_skb_ext_load_rx_csum

They return only the stored values. The RX metadata kfuncs above still
read the values from the RX descriptor. Unlike those, the kfuncs in this
section do not need a program that is bound to a device.

On ``AF_XDP`` zero-copy, the store kfuncs return ``-EOPNOTSUPP``, because
user space can write the headroom. The area would not reach the skb
anyway. On ``XDP_REDIRECT``, ``xdp_convert_zc_to_xdp_frame`` copies only
the custom metadata and the packet. On ``XDP_PASS``, drivers do not apply
the area.

AF_XDP
======

:doc:`af_xdp` use-case implies that there is a contract between the BPF
program that redirects XDP frames into the ``AF_XDP`` socket (``XSK``) and
the final consumer. Thus the BPF program manually allocates a fixed number of
bytes out of metadata via ``bpf_xdp_adjust_meta`` and calls a subset
of kfuncs to populate it. The userspace ``XSK`` consumer computes
``xsk_umem__get_data() - METADATA_SIZE`` to locate that metadata.
Note, ``xsk_umem__get_data`` is defined in ``libxdp`` and
``METADATA_SIZE`` is an application-specific constant (``AF_XDP`` receive
descriptor does _not_ explicitly carry the size of the metadata).

Here is the ``AF_XDP`` consumer layout (note missing ``data_meta`` pointer)::

  +----------+-----------------+------+
  | headroom | custom metadata | data |
  +----------+-----------------+------+
                               ^
                               |
                        rx_desc->address

XDP_PASS
========

This is the path where the packets processed by the XDP program are passed
into the kernel. The kernel creates the ``skb`` out of the ``xdp_buff``
contents. Currently, every driver has custom kernel code to parse
the descriptors and populate ``skb`` metadata when doing this ``xdp_buff->skb``
conversion, and the custom metadata is not used by the kernel when building
``skbs``. However, TC-BPF programs can access the XDP metadata area using
the ``data_meta`` pointer.

On drivers with the ``skb-ext-pass`` XDP feature, an XDP program can use
the `SKB Core Extension Area`_ to override the hash, VLAN tag and checksum
status of the ``skb``.

bpf_redirect_map
================

``bpf_redirect_map`` can redirect the frame to a different device.
Some devices (like virtual ethernet links) support running a second XDP
program after the redirect. However, the final consumer doesn't have
access to the original hardware descriptor and can't access any of
the original metadata. The same applies to XDP programs installed
into devmaps and cpumaps.

This means that the initial XDP program has to prepare the metadata
before the redirect, as custom metadata or in the `SKB Core Extension
Area`_. If the frame is eventually passed to the kernel, the ``skb``
created from such a frame gets its hash, VLAN tag and checksum status
only from the area. If such a packet is later redirected into an
``XSK``, that will only have access to the custom metadata.

bpf_tail_call
=============

Adding programs that access metadata kfuncs to the ``BPF_MAP_TYPE_PROG_ARRAY``
is currently not supported. The kfuncs of the `SKB Core Extension Area`_
do not have this limit.

Supported Devices
=================

It is possible to query which kfunc the particular netdev implements via
netlink. See ``xdp-rx-metadata-features`` attribute set in
``Documentation/netlink/specs/netdev.yaml``.

A netdev that sets the values from the `SKB Core Extension Area`_ on
``XDP_PASS`` in native XDP has the ``skb-ext-pass`` flag in its
``xdp-features`` attribute. The flag does not cover generic XDP or the
veth ``skb`` path. An XDP program can also read ``xdp_features`` of the
receiving netdev after ``bpf_cast_to_kern_ctx``.

Driver Implementation
=====================

Certain devices may prepend metadata to received packets. However, as of now,
``AF_XDP`` lacks the ability to communicate the size of the ``data_meta`` area
to the consumer. Therefore, it is the responsibility of the driver to copy any
device-reserved metadata out from the metadata area and ensure that
``xdp_buff->data_meta`` is pointing to ``xdp_buff->data`` before presenting the
frame to the XDP program. This is necessary so that, after the XDP program
adjusts the metadata area, the consumer can reliably retrieve the metadata
address using ``METADATA_SIZE`` offset.

The following diagram shows how custom metadata is positioned relative to the
packet data and how pointers are adjusted for metadata access::

              |<-- bpf_xdp_adjust_meta(xdp_buff, -METADATA_SIZE) --|
  new xdp_buff->data_meta                              old xdp_buff->data_meta
              |                                                    |
              |                                            xdp_buff->data
              |                                                    |
   +----------+----------------------------------------------------+------+
   | headroom |                  custom metadata                   | data |
   +----------+----------------------------------------------------+------+
              |                                                    |
              |                                            xdp_desc->addr
              |<------ xsk_umem__get_data() - METADATA_SIZE -------|

``bpf_xdp_adjust_meta`` ensures that ``METADATA_SIZE`` is aligned to 4 bytes,
does not exceed 252 bytes, and leaves sufficient space for building the
xdp_frame. If these conditions are not met, it returns a negative error. In this
case, the BPF program should not proceed to populate data into the ``data_meta``
area.

A driver that builds the ``skb`` on ``XDP_PASS`` applies the
`SKB Core Extension Area`_ and sets ``NETDEV_XDP_ACT_SKB_EXT_PASS``. The
driver sets the ``skb`` fields from the RX descriptor and then calls this
function. The driver takes the area pointer with ``xdp_buff_skb_ext``
before it reuses the ``xdp_buff``:

.. kernel-doc:: net/core/xdp.c
   :identifiers: xdp_skb_ext_to_skb

``xdp_build_skb_from_frame`` does not apply the area. Its callers set the
RX fields themselves or transmit the ``skb``.

A driver that moves ``data_hard_start`` after the XDP program ran calls
``xdp_buff_clear_skb_ext_flag``, because the area is no longer at the
expected place. The stored values are then lost.

Example
=======

See ``tools/testing/selftests/bpf/progs/xdp_metadata.c`` and
``tools/testing/selftests/bpf/prog_tests/xdp_metadata.c`` for an example of
BPF program that handles XDP metadata. See
``tools/testing/selftests/bpf/progs/test_xdp_skb_ext.c`` and
``tools/testing/selftests/bpf/prog_tests/xdp_skb_ext.c`` for the skb core
extension area, and ``tools/testing/selftests/drivers/net/hw/xdp_metadata.py``
for a driver on ``XDP_PASS``.
