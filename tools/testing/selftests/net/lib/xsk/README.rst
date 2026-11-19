.. SPDX-License-Identifier: GPL-2.0

==========
xskxceiver
==========

The AF_XDP engine in ``net/lib/xsk`` is built as ``net/lib/xskxceiver``.
``drivers/net/xsk.py`` runs it against an SKB-mode remote endpoint, over
veth in SKB and DRV mode, or in zero-copy mode on a NIC.

Each ``xskxceiver`` endpoint generates and validates raw UDP frames over
IPv4 or IPv6. It sends them from ``--src-ip`` to ``--dst-ip``, the address
of its peer, via ``--dst-mac``, the MAC address of its next hop to the
peer, and to UDP port ``--udp-port``. Over IPv4, the UDP checksum is
zero. The UDP source port tells the sockets of ``XDP_SHARED_UMEM`` apart.
The endpoints do not use AF_INET sockets for the test traffic. The XDP
programs redirect only UDP packets to ``--udp-port`` and pass all other
traffic to the stack.

Runner
======

``xsk.py`` starts one ``xskxceiver`` process on the local interface and
one on the remote interface for each case, and owns the TAP results. It
starts the local endpoint first. That one listens on a TCP control port
(``--listen``) on the local address, and the remote endpoint connects to
it over the tested link. The listener reports on ``KSFT_READY_FD`` once it
listens, so ``xsk.py`` starts the remote endpoint without polling for the
port. The listener waits 10 seconds for its peer. The small per-case
channel reports readiness, packet progress, skips, and aborts. It has no
capabilities or verdict handshake. ``xsk.py`` chooses the case, sets the
timeouts, and reports the result from both process exit codes. Each
endpoint sees only its own device and mode. One that skips a case tells
its peer on the control channel, which skips the case as well, and
``xsk.py`` reports a case as skipped when one endpoint skips it and the
other skips or passes it. Killing an SSH client does not stop the command
it runs, so both endpoints run under ``timeout(1)``.

The endpoints send UDP over IPv6, or over IPv4 when ``NETIF`` comes
without ``LOCAL_V6`` and ``REMOTE_V6``, between the addresses of the two
interfaces. Each sends to the MAC address of its next hop to the other,
which is the peer interface on a shared link and the gateway otherwise.
``xsk.py`` picks the UDP port at random for the run and the control port
for each case. As the XDP programs pass the control connection and all
other traffic to the stack, the tested link does not have to be otherwise
idle.

Each endpoint detaches its XDP program and restores the MTU before it
exits, and after an endpoint fails or is killed, ``xsk.py`` does so
itself. ``xsk.py`` reserves 32 huge pages of 2 MiB for the UNALIGNED cases
on both hosts or on neither, and restores the count however the run ends.
Without them, it reports the UNALIGNED cases as expected failures (XFAIL)
without running them.

``xskxceiver -l`` lists each case with the roles that it tests on
hardware, e.g. ``0: SEND_RECEIVE rx tx``, or with none if it runs over
veth only. The remote endpoint always runs in SKB mode and does not busy
poll, so only the local endpoint takes the mode and busy polling of a
case.

``test_xsk`` runs each case with the local endpoint driven by interrupts.
On a NIC, ``test_xsk_busy_poll`` runs the same cases again with the local
endpoint busy polling, e.g. ``-t 'test_xsk_busy_poll.*'``. Each of its
cases sets ``napi_defer_hard_irqs`` and ``gro_flush_timeout`` on the local
interface and restores them when it ends. ``xsk.py -l`` lists the cases,
``-t`` selects them, and without ``-t`` all cases run.

veth
====

Without ``NETIF``, ``NetDrvEpEnv`` creates a veth pair for the run, with
the remote end in a network namespace of its own, and both endpoints bind
queue 0. For example::

  make -C tools/testing/selftests/net/lib
  cd tools/testing/selftests/drivers/net
  sudo ./xsk.py

``xsk.py`` runs each case that ``xskxceiver -l`` lists in SKB and DRV
mode, with the local endpoint receiving in that mode, e.g.
``test_xsk.drv_SEND_RECEIVE``, and ``-t 'test_xsk.drv_*'`` selects the DRV
mode cases. A copy-mode socket sends alike in both modes, so the SKB-mode
remote endpoint sends as a DRV-mode one would. veth does not tie its NAPI
instances to its queues, so a socket on it has no NAPI to busy poll, and
a veth run has no ``test_xsk_busy_poll`` cases.

The cases that cannot pass over veth are reported as expected failures
(XFAIL) without being run:

- ``XDP_ADJUST_TAIL_SHRINK_MULTI_BUFF``, as it leaks page_pool pages on
  veth
- ``XDP_ADJUST_TAIL_GROW`` and ``XDP_ADJUST_TAIL_GROW_MULTI_BUFF``, as
  generic XDP leaves no room to grow the tail, and veth leaves no room to
  grow most frames and cannot grow frags
- ``HW_SW_MIN_RING_SIZE`` and ``HW_SW_MAX_RING_SIZE``, as veth has no
  ethtool rings
- ``STAT_RX_DROPPED``, when ``net.core.max_skb_frags`` is not 17. Only the
  initial network namespace has the sysctl, so the remote endpoint takes
  17, and each endpoint sizes its UMEM tailroom for the case by its own
  value.

For ``TOO_MANY_FRAGS``, ``xsk.py`` passes ``net.core.max_skb_frags`` plus
one to both endpoints.

NIC
===

With ``NETIF`` set, ``xsk.py`` runs each case that ``xskxceiver -l``
lists with a role, once in each role listed with it. ``test_xsk.h`` groups
the cases by the DUT roles in which they run.

The DUT runs in ZC mode; the remote runs in SKB mode and does not need
zero-copy. RX and TX cases are named separately in TAP, e.g.
``test_xsk.rx_SEND_RECEIVE`` and ``test_xsk.tx_SEND_RECEIVE``. ``xsk.py``
skips a DUT that does not advertise AF_XDP zero-copy. The DUT endpoint
binds with ``XDP_ZEROCOPY``, which fails instead of falling back to copy
mode, so an advertised device that cannot bind or run a case fails it.

``xsk.py`` takes the last DUT queue that has both an RX and a TX ring out
of RSS and binds the DUT endpoint to it. For DUT RX cases it steers the
test flow to that queue with an ntuple rule, and for DUT TX cases to
queue 0 on the remote receiver. A TX-only zero-copy socket fills no RX
buffers, so its queue drops what it receives, and TX cases keep that queue
out of RSS as well. Accelerated RFS, which ntuple filters turn on in some
drivers, could still steer the control connection to that queue, so RFS
has to stay off on the DUT, as it is by default.

Turning ntuple filters on can reset the NIC, so ``xsk.py`` does that
before it takes the queue out of RSS. A driver that rebuilds its RSS
indirection table on every reset still puts the queue back into RSS when
a case attaches an XDP program or changes the MTU or ring sizes. A case
fails if the queue is back in RSS once it has cleaned up, and ``xsk.py``
then takes the queue out of RSS again for the next case.

``xsk.py`` sets up the queue, the ntuple rules and huge pages for the
UNALIGNED cases once, before the cases run, and undoes them however the
run ends. The run is skipped when either host has no ntuple support or
rejects the ntuple rule. Cases that do not need larger frames default to
an MTU of 1500 (``ETH_DATA_LEN``), and the SKB-mode remote endpoint only
raises its MTU when a case needs a larger one, as changing the MTU can
reset the NIC. Before the endpoints start, ``xsk.py`` sets with
``ethtool -G`` the TX ring of the sending interface to 64 descriptors
for HW_SW_MIN_RING_SIZE, and for HW_SW_MAX_RING_SIZE the TX ring of the
sending interface and the RX ring of the receiving one to their maximum
sizes, which can reset the NIC as well. Once both endpoints are ready,
each waits for its link before sending, as such a reset can take the
link down on both hosts, and ``xsk.py`` raises the traffic and link
timeouts of the endpoints to 20 seconds with ``--timeout``. When the run
ends, the runner resets the RSS indirection table of the DUT with
``ethtool -X default``, writes the saved table back if it was not the
default, and restores the ntuple setting and the huge-page count. It
restores the ring sizes after the case however the endpoints end. A host
whose ring sizes ``ethtool -g`` cannot read skips the two ring cases.
The runner does not change channel counts. A DUT with fewer than two
queues that have both rings skips all cases, as it has no queue to take
out of RSS. So does a DUT that cannot take one out of RSS.

The remote is either another host (``REMOTE_TYPE=ssh``) or the peer port
of the same host moved to a network namespace (``REMOTE_TYPE=netns``).
The framework runs the remote commands for either backend. Both endpoints
run as root.

Setup
-----

Build the engine on the DUT::

  make -C tools/testing/selftests/net/lib

A top-level selftests build with ``TARGETS=drivers/net`` includes
``net/lib`` as well.

Configure the usual driver test variables in
``tools/testing/selftests/drivers/net/net.config`` or the environment::

  NETIF=eth0
  LOCAL_V4=192.0.2.1
  REMOTE_V4=192.0.2.2
  REMOTE_TYPE=netns
  REMOTE_ARGS=xsk-peer

Set ``LOCAL_V6`` and ``REMOTE_V6`` as well to test over IPv6, with the
addresses added ``nodad``. ``REMOTE_ARGS`` names the namespace that holds
the peer port. With eth0 connected back to back to eth1 of the same host,
set it up as root::

  ip netns add xsk-peer
  ip link set eth1 netns xsk-peer
  ip -n xsk-peer link set lo up
  ip -n xsk-peer addr add 192.0.2.2/24 dev eth1
  ip -n xsk-peer link set eth1 up
  ip addr add 192.0.2.1/24 dev eth0
  ip link set eth0 up

Run as root on the DUT::

  cd tools/testing/selftests/drivers/net
  sudo ./xsk.py -t test_xsk.rx_SEND_RECEIVE

``xskxceiver -l`` lists the cases, and ``xsk.py -l`` the names to pass to
``-t``. Set the variables in ``net.config`` when using ``sudo`` so they
are available to the test process.

With SSH, each case starts its remote endpoint over SSH. SSH connection
sharing for the remote host (``ControlMaster``, ``ControlPath`` and
``ControlPersist`` in ssh_config(5)) avoids a new SSH login for each remote
command. With ``sudo``, that is root's SSH configuration.

The remote host needs AF_XDP in SKB mode and BPF, and both hosts need
``timeout(1)``. In a namespace, the remote endpoint runs the DUT's
``xskxceiver`` binary. With SSH, ``xsk.py`` copies that binary to the
remote, so both hosts must have compatible architectures and libraries.
The DUT needs RSS support, and both hosts need ntuple support. The test
uses ``NetDrvEpEnv`` and the networking selftest Python helpers for setup
and rollback.

The hardware cases cover baseline traffic, 2K frames, single packets,
poll, headroom, invalid TX descriptors, socket statistics, XDP program
cleanup, XDP drop, metadata, tail adjustment, multi-buffer, 9K,
unaligned traffic, HW ring sizes, socket teardown, and shared UMEM.
For ``TOO_MANY_FRAGS``, the runner reads the DUT's ``xdp-zc-max-segs``
value and passes it to both endpoint processes so the SKB peer validates
the same packet stream without a capabilities exchange. A DUT without
multi-buffer zero-copy skips the case, as it does the other multi-buffer
cases.
