==================
AF_XDP TX Metadata
==================

This document describes how to enable offloads when transmitting packets
via :doc:`af_xdp`. Refer to :doc:`xdp-rx-metadata` on how to access similar
metadata on the receive side.

General Design
==============

The headroom for the metadata is reserved via ``setsockopt(fd, SOL_XDP,
XDP_TX_METADATA_LEN, &len, 4)``. The metadata layout is a fixed UAPI,
refer to ``struct xsk_tx_metadata`` in ``include/uapi/linux/if_xdp.h``.
IOW, the ``len`` variable above should contain
``sizeof(struct xsk_tx_metadata)``.

The headroom and the metadata itself should be located right before
``xdp_desc->addr`` in the umem frame. Within a frame, the metadata
layout is as follows::

         XDP_TX_METADATA_LEN
     /                         \
    +-----------------+---------+----------------------------+
    | xsk_tx_metadata | padding |          payload           |
    +-----------------+---------+----------------------------+
                                ^
                                |
                          xdp_desc->addr

An AF_XDP applications can request headrooms larger than ``sizeof(struct
xsk_tx_metadata)``. The kernel will ignore the padding (and will still
use ``xdp_desc->addr - XDP_TX_METADATA_LEN`` to locate
the ``xsk_tx_metadata``). The application is expected to zero-out
the metadata flags for the frames that shouldn't use any offloads.

The flags field enables the particular offload:

- ``XDP_TX_METADATA_TIMESTAMP``: requests the device to put transmission
  timestamp into ``tx_timestamp`` field of ``struct xsk_tx_metadata``.
- ``XDP_TX_METADATA_CHECKSUM``: requests the device to calculate L4
  checksum. ``csum_start`` specifies byte offset of there the checksumming
  should start and ``csum_offset`` specifies byte offset where the
  device should store the computed checksum.
- ``XDP_TX_METADATA_CHECKSUM_SW``: requests checksum calculation to
  be done in software; this mode works only in ``XSK_COPY`` mode and
  is mostly intended for testing. Do not enable this option, it
  will negatively affect performance.

Besides the flags above, in order to trigger the offloads, the first
packet's ``struct xdp_desc`` descriptor should set ``XDP_TX_METADATA``
bit in the ``options`` field. Also not that in a multi-buffer packet
only the first chunk should carry the metadata.

Querying Device Capabilities
============================

Every devices exports its offloads capabilities via netlink netdev family.
Refer to ``xsk-flags`` features bitmask in
``Documentation/netlink/specs/netdev.yaml``.

- ``tx-timestamp``: device supports ``XDP_TX_METADATA_TIMESTAMP``
- ``tx-checksum``: device supports ``XDP_TX_METADATA_CHECKSUM``

Note that every devices supports ``XDP_TX_METADATA_CHECKSUM_SW`` when
running in ``XSK_COPY`` mode.

See ``tools/net/ynl/samples/netdev.c`` on how to query this information.

Example
=======

See ``tools/testing/selftests/bpf/xdp_hw_metadata.c`` for an example
program that handles TX metadata. Also see https://github.com/fomichev/xskgen
for a more bare-bones example.
