.. SPDX-License-Identifier: GPL-2.0

============
Rmnet Driver
============

1. Introduction
===============

rmnet driver is used for supporting the Multiplexing and aggregation
Protocol (MAP). This protocol is used by all recent chipsets using Qualcomm
Technologies, Inc. modems.

This driver can be used to register onto any physical network device in
IP mode. Physical transports include USB, HSIC, PCIe and IP accelerator.

Multiplexing allows for creation of logical netdevices (rmnet devices) to
handle multiple private data networks (PDN) like a default internet, tethering,
multimedia messaging service (MMS) or IP media subsystem (IMS). Hardware sends
packets with MAP headers to rmnet. Based on the multiplexer id, rmnet
routes to the appropriate PDN after removing the MAP header.

Aggregation is required to achieve high data rates. This involves hardware
sending aggregated bunch of MAP frames. rmnet driver will de-aggregate
these MAP frames and send them to appropriate PDN's.

2. Packet format
================

a. MAP packet v1 (data / control)
---------------------------------

MAP header fields are in big endian format.

Packet format::

  Bit             0             1           2-7      8-15           16-31
  Function   Command / Data   Reserved     Pad   Multiplexer ID    Payload length

  Bit            32-x
  Function      Raw bytes

Command (1)/ Data (0) bit value is to indicate if the packet is a MAP command
or data packet. Command packet is used for transport level flow control. Data
packets are standard IP packets.

Reserved bits must be zero when sent and ignored when received.

Padding is the number of bytes to be appended to the payload to
ensure 4 byte alignment.

Multiplexer ID is to indicate the PDN on which data has to be sent.

Payload length includes the padding length but does not include MAP header
length.

b. Map packet v4 (data / control)
---------------------------------

MAP header fields are in big endian format.

Packet format::

  Bit             0             1           2-7      8-15           16-31
  Function   Command / Data   Reserved     Pad   Multiplexer ID    Payload length

  Bit            32-(x-33)      (x-32)-x
  Function      Raw bytes      Checksum offload header

Command (1)/ Data (0) bit value is to indicate if the packet is a MAP command
or data packet. Command packet is used for transport level flow control. Data
packets are standard IP packets.

Reserved bits must be zero when sent and ignored when received.

Padding is the number of bytes to be appended to the payload to
ensure 4 byte alignment.

Multiplexer ID is to indicate the PDN on which data has to be sent.

Payload length includes the padding length but does not include MAP header
length.

Checksum offload header, has the information about the checksum processing done
by the hardware.Checksum offload header fields are in big endian format.

Packet format::

  Bit             0-14        15              16-31
  Function      Reserved   Valid     Checksum start offset

  Bit                31-47                    48-64
  Function      Checksum length           Checksum value

Reserved bits must be zero when sent and ignored when received.

Valid bit indicates whether the partial checksum is calculated and is valid.
Set to 1, if its is valid. Set to 0 otherwise.

Padding is the number of bytes to be appended to the payload to
ensure 4 byte alignment.

Checksum start offset, Indicates the offset in bytes from the beginning of the
IP header, from which modem computed checksum.

Checksum length is the Length in bytes starting from CKSUM_START_OFFSET,
over which checksum is computed.

Checksum value, indicates the checksum computed.

c. MAP packet v5 (data / control)
---------------------------------

MAP header fields are in big endian format.

Packet format::

  Bit             0             1         2-7      8-15           16-31
  Function   Command / Data  Next header  Pad   Multiplexer ID   Payload length

  Bit            32-x
  Function      Raw bytes

Command (1)/ Data (0) bit value is to indicate if the packet is a MAP command
or data packet. Command packet is used for transport level flow control. Data
packets are standard IP packets.

Next header is used to indicate the presence of another header, currently
limited to the checksum and coalescing headers.

Padding is the number of bytes to be appended to the payload to
ensure 4 byte alignment.

Multiplexer ID is to indicate the PDN on which data has to be sent.

Payload length includes the padding length but does not include MAP header
length.

d. Checksum offload header v5
-----------------------------

Checksum offload header fields are in big endian format.

Packet format::

  Bit            0 - 6          7               8-15              16-31
  Function     Header Type    Next Header     Checksum Valid    Reserved

Header Type is to indicate the type of header, this usually is set to CHECKSUM

Header types

= ======================
0 Reserved
1 coalescing header
2 checksum header
= ======================

Checksum Valid is to indicate whether the header checksum is valid. Value of 1
implies that checksum is calculated on this packet and is valid, value of 0
indicates that the calculated packet checksum is invalid.

Reserved bits must be zero when sent and ignored when received.

e. Coalescing header v5
------------------------

Hardware can coalesce multiple same-flow IP packets of the same length into
a single MAP frame to reduce per-packet overhead at high data rates.  The
coalescing header (header type 1) describes the coalesced content.

Packet format::

  Bit         0 - 6         7          8           9-11         12-15
  Function  Header Type  Next Header  CSUM valid  Num NLOs    (reserved)

  Bit        16-19        20-23
  Function  Close value  Close type

  Bit        24-27        28-31
  Function  (reserved)    VEID

  Bit           32 - 47        48 - 55            56 - 63
  Function   Packet length  CSUM error bitmap  Num packets (NLO 0)

  ... (up to 6 NLO entries total, same 32-bit format per entry)

Header Type is set to 1 (coalescing).

Num NLOs (Number-Length Objects) is the count of active NLO entries
(1 – 6).  Each NLO describes a group of consecutive coalesced packets
that all share the same IP packet length.

CSUM valid (bit 8) indicates whether the hardware checksum is valid
for all packets in the frame.

Close type and close value encode the hardware reason that coalescing
was terminated for this frame:

Close type values:

= ==============================
0 non-coalesced (single packet)
1 IP flow miss
2 transport flow miss
3 hardware limit (see value)
4 coalescing closed (FIN/PSH)
= ==============================

Close value (used when close type is 3):

= ==================
0 NL limit reached
1 packet limit
2 byte limit
3 time limit
4 eviction
= ==================

VEID is the virtual endpoint ID of the originating flow.

Each NLO entry::

  Bit         0 - 15        16 - 23            24 - 31
  Function  Pkt length   CSUM error bitmap   Num packets

Pkt length is the full IP packet length, including the IP header,
transport header, and payload, for every packet in this NLO group.

CSUM error bitmap is a per-packet bitmask. Bit N is set when packet N
in this NLO has a bad checksum.

Num packets is the count of coalesced packets described by this NLO.

f. MAP packet v1/v5 (command specific)
---------------------------------------

Packet format::

    Bit             0             1         2-7      8 - 15           16 - 31
    Function   Command         Reserved     Pad   Multiplexer ID    Payload length
    Bit          32 - 39        40 - 45    46 - 47       48 - 63
    Function   Command name    Reserved   Command Type   Reserved
    Bit          64 - 95
    Function   Transaction ID
    Bit          96 - 127
    Function   Command data

Command 1 indicates disabling flow while 2 is enabling flow

Command types

= ==========================================
0 for MAP command request
1 is to acknowledge the receipt of a command
2 is for unsupported commands
3 is for error during processing of commands
= ==========================================

g. Aggregation
--------------

Aggregation is multiple MAP packets (can be data or command) delivered to
rmnet in a single linear skb. rmnet will process the individual
packets and either ACK the MAP command or deliver the IP packet to the
network stack as needed

Packet format::

  MAP header|IP Packet|Optional padding|MAP header|IP Packet|Optional padding....

  MAP header|IP Packet|Optional padding|MAP header|Command Packet|Optional pad...

3. Userspace configuration
==========================

rmnet userspace configuration is done through netlink using iproute2
https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/

The driver uses rtnl_link_ops for communication.

The data format flags controlling the ingress and egress processing
pipeline are set via the ``IFLA_RMNET_FLAGS`` attribute
(``struct ifla_rmnet_flags``).

Relevant ingress flags:

``RMNET_FLAGS_INGRESS_DEAGGREGATION``
  Enable MAP frame de-aggregation.

``RMNET_FLAGS_INGRESS_MAP_CKSUMV4``
  Enable MAPv4 downlink checksum offload.

``RMNET_FLAGS_INGRESS_MAP_CKSUMV5``
  Enable MAPv5 downlink checksum offload (header type 2).

``RMNET_FLAGS_INGRESS_COALESCE``
  Enable MAPv5 downlink hardware coalescing (header type 1).
  When set the driver will decode coalescing headers, reconstruct
  individual IP packets and will deliver batched GSO SKBs to the
  stack for efficient processing.

Relevant egress flags:

``RMNET_FLAGS_EGRESS_MAP_CKSUMV4``
  Enable MAPv4 uplink checksum offload.

``RMNET_FLAGS_EGRESS_MAP_CKSUMV5``
  Enable MAPv5 uplink checksum offload.
