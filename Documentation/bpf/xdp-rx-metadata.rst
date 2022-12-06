===============
XDP RX Metadata
===============

XDP programs support creating and passing custom metadata via
``bpf_xdp_adjust_meta``. This metadata can be consumed by the following
entities:

1. ``AF_XDP`` consumer.
2. Kernel core stack via ``XDP_PASS``.
3. Another device via ``bpf_redirect_map``.
4. Other BPF programs via ``bpf_tail_call``.

General Design
==============

XDP has access to a set of kfuncs to manipulate the metadata. Every
device driver implements these kfuncs. The set of kfuncs is
declared in ``include/net/xdp.h`` via ``XDP_METADATA_KFUNC_xxx``.

Currently, the following kfuncs are supported. In the future, as more
metadata is supported, this set will grow:

- ``bpf_xdp_metadata_rx_timestamp_supported`` returns true/false to
  indicate whether the device supports RX timestamps
- ``bpf_xdp_metadata_rx_timestamp`` returns packet RX timestamp
- ``bpf_xdp_metadata_rx_hash_supported`` returns true/false to
  indicate whether the device supports RX hash
- ``bpf_xdp_metadata_rx_hash`` returns packet RX hash

Within the XDP frame, the metadata layout is as follows::

  +----------+-----------------+------+
  | headroom | custom metadata | data |
  +----------+-----------------+------+
             ^                 ^
             |                 |
   xdp_buff->data_meta   xdp_buff->data

AF_XDP
======

``AF_XDP`` use-case implies that there is a contract between the BPF program
that redirects XDP frames into the ``XSK`` and the final consumer.
Thus the BPF program manually allocates a fixed number of
bytes out of metadata via ``bpf_xdp_adjust_meta`` and calls a subset
of kfuncs to populate it. User-space ``XSK`` consumer, looks
at ``xsk_umem__get_data() - METADATA_SIZE`` to locate its metadata.

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
into the kernel. The kernel creates ``skb`` out of the ``xdp_buff`` contents.
Currently, every driver has a custom kernel code to parse the descriptors and
populate ``skb`` metadata when doing this ``xdp_buff->skb`` conversion.
In the future, we'd like to support a case where XDP program can override
some of that metadata.

The plan of record is to make this path similar to ``bpf_redirect_map``
so the program can control which metadata is passed to the skb layer.

bpf_redirect_map
================

``bpf_redirect_map`` can redirect the frame to a different device.
In this case we don't know ahead of time whether that final consumer
will further redirect to an ``XSK`` or pass it to the kernel via ``XDP_PASS``.
Additionally, the final consumer doesn't have access to the original
hardware descriptor and can't access any of the original metadata.

For this use-case, only custom metadata is currently supported. If
the frame is eventually passed to the kernel, the skb created from such
a frame won't have any skb metadata. The ``XSK`` consumer will only
have access to the custom metadata.

bpf_tail_call
=============

No special handling here. Tail-called program operates on the same context
as the original one.
