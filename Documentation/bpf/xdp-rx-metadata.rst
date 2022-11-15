===============
XDP RX Metadata
===============

XDP programs support creating and passing custom metadata via
``bpf_xdp_adjust_meta``. This metadata can be consumed by the following
entities:

1. ``AF_XDP`` consumer.
2. Kernel core stack via ``XDP_PASS``.
3. Another device via ``bpf_redirect_map``.

General Design
==============

XDP has access to a set of kfuncs to manipulate the metadata. Every
device driver implements these kfuncs by generating BPF bytecode
to parse it out from the hardware descriptors. The set of kfuncs is
declared in ``include/net/xdp.h`` via ``XDP_METADATA_KFUNC_xxx``.

Currently, the following kfuncs are supported. In the future, as more
metadata is supported, this set will grow:

- ``bpf_xdp_metadata_rx_timestamp_supported`` returns true/false to
  indicate whether the device supports RX timestamps in general
- ``bpf_xdp_metadata_rx_timestamp`` returns packet RX timestamp or 0
- ``bpf_xdp_metadata_export_to_skb`` prepares metadata layout that
  the kernel will be able to consume. See ``bpf_redirect_map`` section
  below for more details.

Within the XDP frame, the metadata layout is as follows::

  +----------+------------------+-----------------+------+
  | headroom | xdp_skb_metadata | custom metadata | data |
  +----------+------------------+-----------------+------+
                                ^                 ^
                                |                 |
                      xdp_buff->data_meta   xdp_buff->data

Where ``xdp_skb_metadata`` is the metadata prepared by
``bpf_xdp_metadata_export_to_skb``. And ``custom metadata``
is prepared by the BPF program via calls to ``bpf_xdp_adjust_meta``.

Note that ``bpf_xdp_metadata_export_to_skb`` doesn't adjust
``xdp->data_meta`` pointer. To access the metadata generated
by ``bpf_xdp_metadata_export_to_skb`` use ``xdp_buf->skb_metadata``.

AF_XDP
======

``AF_XDP`` use-case implies that there is a contract between the BPF program
that redirects XDP frames into the ``XSK`` and the final consumer.
Thus the BPF program manually allocates a fixed number of
bytes out of metadata via ``bpf_xdp_adjust_meta`` and calls a subset
of kfuncs to populate it. User-space ``XSK`` consumer, looks
at ``xsk_umem__get_data() - METADATA_SIZE`` to locate its metadata.

Here is the ``AF_XDP`` consumer layout (note missing ``data_meta`` pointer)::

  +----------+------------------+-----------------+------+
  | headroom | xdp_skb_metadata | custom metadata | data |
  +----------+------------------+-----------------+------+
                                                  ^
                                                  |
                                           rx_desc->address

XDP_PASS
========

This is the path where the packets processed by the XDP program are passed
into the kernel. The kernel creates ``skb`` out of the ``xdp_buff`` contents.
Currently, every driver has a custom kernel code to parse the descriptors and
populate ``skb`` metadata when doing this ``xdp_buff->skb`` conversion.
In the future, we'd like to support a case where XDP program can override
some of that metadata.

The plan of record is to make this path similar to ``bpf_redirect_map``
below where the program would call ``bpf_xdp_metadata_export_to_skb``,
override the metadata and return ``XDP_PASS``. Additional work in
the drivers will be required to enable this (for example, to skip
populating ``skb`` metadata from the descriptors when
``bpf_xdp_metadata_export_to_skb`` has been called).

bpf_redirect_map
================

``bpf_redirect_map`` can redirect the frame to a different device.
In this case we don't know ahead of time whether that final consumer
will further redirect to an ``XSK`` or pass it to the kernel via ``XDP_PASS``.
Additionally, the final consumer doesn't have access to the original
hardware descriptor and can't access any of the original metadata.

To support passing metadata via ``bpf_redirect_map``, there is a
``bpf_xdp_metadata_export_to_skb`` kfunc that populates a subset
of metadata into ``xdp_buff``. The layout is defined in
``struct xdp_skb_metadata``.

Mixing custom metadata and xdp_skb_metadata
===========================================

For the cases of ``bpf_redirect_map``, where the final consumer isn't
known ahead of time, the program can store both, custom metadata
and ``xdp_skb_metadata`` for the kernel consumption.

Current limitation is that the program cannot adjust ``data_meta`` (via
``bpf_xdp_adjust_meta``) after a call to ``bpf_xdp_metadata_export_to_skb``.
So it has to, first, prepare its custom metadata layout and only then,
optionally, store ``xdp_skb_metadata`` via a call to
``bpf_xdp_metadata_export_to_skb``.
