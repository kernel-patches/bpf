.. SPDX-License-Identifier: GPL-2.0

=========================
TC queue based filtering
=========================

TC can be used for directing traffic to either a set of queues or
to a single queue on both the transmit and receive side.

On the transmit side:

1) TC filter directing traffic to a set of queues is achieved
   using the action skbedit priority for Tx priority selection,
   the priority maps to a traffic class (set of queues) when
   the queue-sets are configured using mqprio.

2) TC filter directs traffic to a transmit queue with the action
   skbedit queue_mapping $tx_qid. The action skbedit queue_mapping
   for transmit queue is executed in software only and cannot be
   offloaded.

Likewise, on the receive side, the two filters for selecting set of
queues and/or a single queue are supported as below:

1) TC flower filter directs incoming traffic to a set of queues using
   the 'hw_tc' option.
   hw_tc $TCID - Specify a hardware traffic class to pass matching
   packets on to. TCID is in the range 0 through 15.

2) TC filter with action skbedit queue_mapping $rx_qid selects a
   receive queue. The action skbedit queue_mapping for receive queue
   is supported only in hardware. Multiple filters may compete in
   the hardware for queue selection. In such case, the hardware
   pipeline resolves conflicts based on priority. On Intel E810
   devices, TC filter directing traffic to a queue have higher
   priority over flow director filter assigning a queue. The hash
   filter has lowest priority.

Tunnel key partitioning splits the key space of a tunnel into blocks. One
filter with a mask on enc_key_id steers a block to its own queue. This
helps with traffic that RSS cannot spread because its hashed fields barely
vary, such as GTP-U tunnels between a few endpoints::

  # GTP-U TEIDs whose two top bits are 01 go to queue 1
  tc filter add dev eth0 ingress protocol ip flower skip_sw \
      ip_proto udp dst_port 2152 enc_key_id 0x40000000/0xc0000000 \
      action skbedit queue_mapping 1 skip_sw

Not all drivers can program a partial mask.

On mlx5 devices such a filter runs on a physical port where nothing
decapsulates the packet. All the keys describe the packet on the wire.
ip_proto and dst_port tell the hardware which tunnel header holds the key.
The software datapath has no tunnel metadata on such a port. The filter
therefore needs skip_sw. Without it the filter stays in software, where
the port reads key zero.

Reducing the number of channels below the queue of a filter drops the
traffic of that filter on mlx5 devices until the channel returns.
