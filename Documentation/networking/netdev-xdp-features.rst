.. SPDX-License-Identifier: GPL-2.0

=====================
Netdev XDP features
=====================

 * XDP FEATURES FLAGS

Following netdev xdp features flags can be retrieved over route netlink
interface (compact form) - the same way as netdev feature flags.
These features flags are read only and cannot be change at runtime.

*  XDP_ABORTED

This feature informs if netdev supports xdp aborted action.

*  XDP_DROP

This feature informs if netdev supports xdp drop action.

*  XDP_PASS

This feature informs if netdev supports xdp pass action.

*  XDP_TX

This feature informs if netdev supports xdp tx action.

*  XDP_REDIRECT

This feature informs if netdev supports xdp redirect action.
It assumes the all beforehand mentioned flags are enabled.

*  XDP_SOCK_ZEROCOPY

This feature informs if netdev driver supports xdp zero copy.
It assumes the all beforehand mentioned flags are enabled.

*  XDP_HW_OFFLOAD

This feature informs if netdev driver supports xdp hw oflloading.

*  XDP_TX_LOCK

This feature informs if netdev ndo_xdp_xmit function requires locking.

*  XDP_REDIRECT_TARGET

This feature informs if netdev implements ndo_xdp_xmit callback.

*  XDP_FRAG_RX

This feature informs if netdev implements non-linear xdp buff support in
the driver napi callback.

*  XDP_FRAG_TARGET

This feature informs if netdev implements non-linear xdp buff support in
ndo_xdp_xmit callback. XDP_FRAG_TARGET requires XDP_REDIRECT_TARGET is properly
supported.
