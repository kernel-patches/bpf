.. SPDX-License-Identifier: GPL-2.0

=====================
Netdev XDP properties
=====================

 * XDP PROPERTIES FLAGS

Following netdev xdp properties flags can be retrieve over netlink ethtool
interface the same way as netdev feature flags. These properties flags are
read only and cannot be change in the runtime.


*  XDP_ABORTED

This property informs if netdev supports xdp aborted action.

*  XDP_DROP

This property informs if netdev supports xdp drop action.

*  XDP_PASS

This property informs if netdev supports xdp pass action.

*  XDP_TX

This property informs if netdev supports xdp tx action.

*  XDP_REDIRECT

This property informs if netdev supports xdp redirect action.
It assumes the all beforehand mentioned flags are enabled.

*  XDP_ZEROCOPY

This property informs if netdev driver supports xdp zero copy.
It assumes the all beforehand mentioned flags are enabled.

*  XDP_HW_OFFLOAD

This property informs if netdev driver supports xdp hw oflloading.
