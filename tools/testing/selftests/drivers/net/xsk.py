#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

"""
AF_XDP tests over veth or a NIC.

Each case runs an xskxceiver endpoint on the local interface and one on the
remote interface. The remote endpoint always runs in SKB mode and does not
busy poll, so the remote needs no zero-copy support. The endpoints send UDP
over IPv6, or over IPv4 if NETIF comes without LOCAL_V6 and REMOTE_V6, each
to the MAC address of its next hop to the other. The local endpoint listens
on a TCP control port on the local address, and the remote endpoint
connects to it once the local one listens. The control connection shares
the tested link, and the XDP programs of both endpoints pass it to the
stack.

"xskxceiver -l" lists each case with the roles that it tests on hardware,
e.g. "0: SEND_RECEIVE rx tx", or with none if a NIC run leaves it out.
test_xsk runs the cases with the local endpoint driven by interrupts, and
on a NIC, test_xsk_busy_poll runs them again with the local endpoint busy
polling. The UNALIGNED cases are reported as expected failures without
being run when either host has no huge pages for them.

Without NETIF, the interfaces are a veth pair with the remote end in a
network namespace of its own. Each listed case runs in SKB and DRV mode,
with the local endpoint receiving in that mode. A copy-mode socket sends
alike in both modes, so the remote endpoint sends as it would in DRV mode.
The variant name starts with the mode, e.g. test_xsk.drv_SEND_RECEIVE. The
cases in VETH_XFAIL cannot pass over veth and are reported as expected
failures without being run. veth does not tie its NAPI instances to its
queues, so a socket on it has no NAPI to busy poll. Only the initial
network namespace has the net.core.max_skb_frags sysctl, so the remote
endpoint takes 17 frags. --max-frags hands the sysctl value to both
endpoints for TOO_MANY_FRAGS, but the cases in TAILROOM_CASES size the
UMEM tailroom by the value of each endpoint, and are expected failures
when the sysctl is not 17.

With NETIF, the local endpoint runs in zero-copy mode on NETIF, the DUT,
and binds to its last queue, and the remote endpoint binds to queue 0.
Before the cases run, main() takes the DUT queue out of RSS and adds an
ntuple filter on each host that steers the test UDP flow to the queue of
the receiving endpoint, and it undoes that however the run ends. A NIC
that rebuilds its RSS indirection table on a reset, such as one for an
XDP, MTU or ring change, puts the queue back into RSS, so a case fails if
the queue is back in RSS after it. Each case runs once for each role
listed with it, with the DUT endpoint in that role, and the variant name
starts with the role, e.g. test_xsk.rx_SEND_RECEIVE. xskxceiver skips the
multi-buffer cases, such as TOO_MANY_FRAGS, on a DUT without multi-buffer
zero-copy.

HW_SW_MIN_RING_SIZE and HW_SW_MAX_RING_SIZE expect the TX ring of the
sending interface, and the latter also the RX ring of the receiving one, at
given sizes. These cases set them with ethtool -G before the endpoints
start, and restore them once the endpoints exit or get killed.
"""

import re
import shlex
import sys
import time
from contextlib import ExitStack
from dataclasses import dataclass

from lib.py import (CmdExitFailure, EthtoolFamily, KsftFailEx,
                    KsftNamedVariant, KsftSkipEx, KsftXfailEx, NetdevFamily,
                    NetDrvEpEnv, NlError, bkg, cmd, defer, ethtool, ip,
                    ksft_eq, ksft_exit, ksft_pr, ksft_run, ksft_variants,
                    rand_port)

# cmd() and bkg() stop waiting for an endpoint that hangs but leave it
# running, as killing ssh does on the remote, and bkg() waits for the local
# endpoint to listen without a time limit, so timeout(1) ends each endpoint.
VETH_CASE_TIMEOUT = 20
NIC_CASE_TIMEOUT = 120
SKIP_CODE = 4
# Traffic and link timeout of the endpoints. veth takes the xskxceiver
# default, and a NIC can take seconds to bring its link back after an MTU or
# XDP change.
VETH_XSK_TIMEOUT = 3
NIC_XSK_TIMEOUT = 20
# The TX ring of the sender and the RX ring of the receiver that a case
# needs at a given size, 64 being the default batch size of xskxceiver.
RING_SIZES = {
    "HW_SW_MIN_RING_SIZE": {"tx": 64},
    "HW_SW_MAX_RING_SIZE": {"tx": "max", "rx": "max"},
}
RING_BUSY_TIMEOUT = 5
NR_HUGEPAGES = 32
# xskxceiver maps the UMEMs of the UNALIGNED cases with MAP_HUGE_2MB.
HUGEPAGES = "/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"
MAX_SKB_FRAGS = "/proc/sys/net/core/max_skb_frags"
# What xskxceiver takes when it cannot read MAX_SKB_FRAGS.
DEFAULT_SKB_FRAGS = 17
# The ip link option that detaches the XDP program of an endpoint mode.
XDP_OFF = {"skb": "xdpgeneric off", "drv": "xdpdrv off", "zc": "xdpdrv off"}
# Why a case cannot pass over veth, by the mode, None for any, and the name.
VETH_XFAIL = {
    # Generic XDP leaves no room to grow the tail, so the RX endpoint skips.
    ("skb", "XDP_ADJUST_TAIL_GROW"): "generic XDP has no tailroom",
    ("skb", "XDP_ADJUST_TAIL_GROW_MULTI_BUFF"): "generic XDP has no tailroom",
    # veth copies each frame into a page_pool fragment that leaves no room
    # to grow the small frames of the case unless it is the last one of its
    # page, so the XDP program drops most frames.
    ("drv", "XDP_ADJUST_TAIL_GROW"): "veth frames have no tailroom",
    # veth registers its XDP RX queues without a frag size, so
    # bpf_xdp_adjust_tail() cannot grow a frag and the RX endpoint skips.
    ("drv", "XDP_ADJUST_TAIL_GROW_MULTI_BUFF"): "veth cannot grow frags",
    # bpf_xdp_adjust_tail() frees a frag that it trims off as the memory type
    # of the XDP RX queue, which veth and generic XDP leave at
    # MEM_TYPE_PAGE_SHARED for frames they copy into page_pool pages, so
    # page_frag_free() frees a page that its pool still owns. The endpoints
    # pass regardless, so running the case would only harm the kernel.
    (None, "XDP_ADJUST_TAIL_SHRINK_MULTI_BUFF"): "trimmed frags leak",
    (None, "HW_SW_MIN_RING_SIZE"): "veth has no HW rings",
    (None, "HW_SW_MAX_RING_SIZE"): "veth has no HW rings",
}
# Cases not in VETH_XFAIL that size the UMEM tailroom by
# net.core.max_skb_frags.
TAILROOM_CASES = ("STAT_RX_DROPPED",)


@dataclass
class Case:
    """The mode and direction of the local endpoint in a case, which
    xskxceiver -t takes as test_id."""
    mode: str
    direction: str
    test_id: int
    name: str


def _get_cases(cfg):
    """
    Each test case from xskxceiver -l comes out in a form below, with the
    roles that it tests on hardware, if any:
    0: SEND_RECEIVE rx tx
    9: POLL_RX rx
    33: BIDIRECTIONAL
    """
    ret = []
    out = cmd([str(cfg.bin_local), "-l"]).stdout
    cases = re.findall(r"^(\d+): (\w+)((?: rx| tx)*)$", out, re.MULTILINE)
    if cfg.veth_test:
        for mode in ("skb", "drv"):
            for test_id, name, _ in cases:
                case = Case(mode, "rx", int(test_id), name)
                ret.append(KsftNamedVariant(f"{mode}_{name}", case))
        return ret

    for test_id, name, roles in cases:
        for direction in roles.split():
            case = Case("zc", direction, int(test_id), name)
            ret.append(KsftNamedVariant(f"{direction}_{name}", case))
    return ret


def _reserve_hugepages(saved, host=None):
    """Raise the count of 2 MiB huge pages on host to what the UNALIGNED
    cases need, and return whether it has that many. Add the count to
    restore to saved, a list for _release_hugepages(), or restore it right
    away if the host falls short. A host without the pool or the rights to
    resize it has no huge pages for the cases."""
    have = cmd(f"cat {HUGEPAGES}", fail=False, host=host)
    if have.ret:
        return False
    have = int(have.stdout)
    if have >= NR_HUGEPAGES:
        return True
    saved.append((host, have))
    cmd(f"echo {NR_HUGEPAGES} > {HUGEPAGES}", shell=True, fail=False,
        host=host)
    if int(cmd(f"cat {HUGEPAGES}", host=host).stdout) >= NR_HUGEPAGES:
        return True
    _release_hugepages([saved.pop()])
    return False


def _release_hugepages(saved):
    """Restore the counts that _reserve_hugepages() added to saved, the last
    one first, as two hosts can share the pool."""
    for host, have in reversed(saved):
        cmd(f"echo {have} > {HUGEPAGES}", shell=True, fail=False, host=host)


def _setup_busy_poll(ifname):
    """Set napi_defer_hard_irqs and gro_flush_timeout of ifname until the
    case ends, so that SO_PREFER_BUSY_POLL of xskxceiver -b keeps the IRQs
    masked."""
    for attr, val in (("napi_defer_hard_irqs", 2),
                      ("gro_flush_timeout", 200000)):
        path = f"/sys/class/net/{ifname}/{attr}"
        old = cmd(f"cat {path}").stdout.strip()
        if old == str(val):
            continue
        cmd(f"echo {val} > {path}", shell=True)
        defer(cmd, f"echo {old} > {path}", shell=True)


def _restore_rss(cfg, indir):
    """Restore the RSS indirection table of the DUT. Reset it to the default
    first, which leaves it to the driver again, and write indir back only if
    it was not the default."""
    ethtool(f"-X {cfg.ifname} default")
    req = {"header": {"dev-index": cfg.ifindex}}
    if cfg.ethnl.rss_get(req).get("indir") != indir:
        cfg.ethnl.rss_set({**req, "indir": indir})


def _reserve_queue(cfg, undo):
    """Take the last queue with both an RX and a TX ring out of RSS until
    undo, return None if the DUT cannot. A TX endpoint fills no RX buffers,
    so in zero-copy mode its queue drops what it receives, the control
    connection included."""
    req = {"header": {"dev-index": cfg.ifindex}}
    try:
        ch = cfg.ethnl.channels_get(req)
        rss = cfg.ethnl.rss_get(req)
    except NlError:
        print(f"1..0 # SKIP cannot get the channels or RSS of {cfg.ifname}")
        return None
    count = ch.get("combined-count", 0) + min(ch.get("rx-count", 0),
                                              ch.get("tx-count", 0))
    if count < 2:
        print("1..0 # SKIP Test requires NETIF with at least 2 channels")
        return None
    queue = count - 1
    if cmd(f"ethtool -X {cfg.ifname} equal {queue}", fail=False).ret:
        print(f"1..0 # SKIP {cfg.ifname} cannot take queue {queue} out of RSS")
        return None
    undo.callback(_restore_rss, cfg, rss.get("indir"))
    return queue


def _check_rss(cfg):
    """Fail the case if the DUT queue is back in RSS, as on a driver that
    rebuilds its indirection table on a reset, and take it out again for
    the next case."""
    req = {"header": {"dev-index": cfg.ifindex}}
    if cfg.queue not in cfg.ethnl.rss_get(req).get("indir", []):
        return
    cmd(f"ethtool -X {cfg.ifname} equal {cfg.queue}", fail=False)
    raise KsftFailEx(f"queue {cfg.queue} of {cfg.ifname} is back in RSS")


def _ntuple_on(undo, ifname, host=None):
    """Turn on ntuple-filters of ifname until undo, return False if it
    cannot."""
    ntuple = ethtool(f"-k {ifname}", json=True, host=host)[0]["ntuple-filters"]
    if ntuple["active"]:
        return True
    if ntuple["fixed"]:
        print(f"1..0 # SKIP {ifname} does not support ntuple-filters")
        return False
    ethtool(f"-K {ifname} ntuple-filters on", host=host)
    undo.callback(ethtool, f"-K {ifname} ntuple-filters off", host=host)
    return True


def _steer_udp(cfg, undo, ifname, queue, host=None):
    """Steer the test flow to queue until undo, return False if ifname
    rejects the ntuple rule."""
    res = cmd(f"ethtool -N {ifname} flow-type udp{cfg.addr_ipver} "
              f"dst-port {cfg.udp_port} action {queue}", host=host, fail=False)
    if res.ret:
        print(f"1..0 # SKIP {ifname} rejects the ntuple rule")
        return False
    rule = re.search(r"ID (\d+)", res.stdout).group(1)
    undo.callback(ethtool, f"-N {ifname} delete {rule}", host=host)
    return True


def _next_hop_mac(cfg, addr, peer_mac, ifname, host=None):
    """Return the MAC address that host sends packets for addr to: peer_mac
    if addr is on link, else the MAC address of the gateway."""
    route = ip(f"-{cfg.addr_ipver} route get {addr}", json=True,
               host=host)[0]
    gw = route.get("gateway")
    if not gw:
        return peer_mac

    # Resolve the gateway, from ifname as an IPv6 one is likely link-local.
    # The ping only triggers ARP or neighbour discovery, so the gateway
    # may ignore it.
    cmd(f"ping -c1 -W1 -I{ifname} {gw}", host=host, fail=False)
    # Unlike "neigh get", "neigh show" has JSON output in older iproute2.
    neigh = ip(f"neigh show {gw} dev {ifname}", json=True, host=host)
    if not neigh or "lladdr" not in neigh[0]:
        raise KsftFailEx(f"cannot resolve the MAC address of gateway {gw}")
    return neigh[0]["lladdr"]


def _set_ring(ifname, ring, size, host=None):
    """Set a ring of ifname with ethtool -G. A driver can refuse that while
    an XSK socket that just closed still holds a queue, as ice does until a
    work item releases the buffer pool of the socket, so retry for a while."""
    deadline = time.monotonic() + RING_BUSY_TIMEOUT
    while True:
        res = cmd(f"ethtool -G {ifname} {ring} {size}", host=host, fail=False)
        if res.ret == 0:
            return
        if "Device or resource busy" not in res.stderr or \
           time.monotonic() > deadline:
            raise CmdExitFailure("Command failed", res)
        time.sleep(0.1)


def _size_rings(cfg, name, direction):
    """Set the rings that case name needs, and restore them after it."""
    for ring, size in RING_SIZES[name].items():
        # The DUT endpoint sends for tx, and receives for rx.
        if ring == direction:
            host, ifname = None, cfg.ifname
        else:
            host, ifname = cfg.remote, cfg.remote_ifname
        try:
            cur = ethtool(f"-g {ifname}", json=True, host=host)[0]
        except CmdExitFailure:
            cur = {}
        if ring not in cur:
            raise KsftSkipEx(f"cannot read the {ring} ring size of {ifname}")
        if size == "max":
            size = cur[f"{ring}-max"]
        if cur[ring] == size:
            continue
        _set_ring(ifname, ring, size, host)
        defer(_set_ring, ifname, ring, cur[ring], host)


def _veth_xfail(cfg, case):
    """Report a case that cannot pass over veth as an expected failure
    without running it."""
    reason = VETH_XFAIL.get((case.mode, case.name),
                            VETH_XFAIL.get((None, case.name)))
    if not reason and case.name in TAILROOM_CASES and \
       cfg.max_skb_frags != DEFAULT_SKB_FRAGS:
        reason = (f"the remote endpoint takes max_skb_frags as "
                  f"{DEFAULT_SKB_FRAGS}, not {cfg.max_skb_frags}")
    if reason:
        raise KsftXfailEx(reason)


def _setup(cfg, case, busy_poll):
    # A case that fails to clean up can leave an XDP program behind, which
    # cfg.dev and cfg.remote_dev, taken before the first case, do not show.
    for ifname, host in ((cfg.ifname, None), (cfg.remote_ifname, cfg.remote)):
        if "xdp" in ip(f"link show dev {ifname}", json=True, host=host)[0]:
            raise KsftSkipEx(f"{ifname} already has an XDP program")
    if not cfg.veth_test:
        # Defers run in reverse, so this runs once the case has cleaned up,
        # which can reset the NIC as well.
        defer(_check_rss, cfg)
    if busy_poll:
        _setup_busy_poll(cfg.ifname)
    if "RING_SIZE" in case.name:
        _size_rings(cfg, case.name, case.direction)

    # Defers run in reverse, so the XDP programs, which can cap the MTU, go
    # first.
    fallbacks = [
        defer(ip, f"link set dev {cfg.ifname} mtu {cfg.dev['mtu']}"),
        defer(ip, f"link set dev {cfg.remote_ifname} "
                  f"mtu {cfg.remote_dev['mtu']}", host=cfg.remote),
        defer(ip, f"link set dev {cfg.ifname} {XDP_OFF[case.mode]}"),
        defer(ip, f"link set dev {cfg.remote_ifname} {XDP_OFF['skb']}",
              host=cfg.remote),
    ]
    return fallbacks


def _check_opt(opt, val, low, high):
    """xskxceiver takes its numeric options as given, so check that val, the
    value of opt, is in low-high before it is passed on."""
    if not low <= val <= high:
        raise ValueError(f"xskxceiver {opt} {val} is not in {low}-{high}")


def _fixup_args(cfg, test_id, ctrl_port):
    cfg.args[cfg.args.index("-t") + 1] = str(test_id)
    cfg.args[cfg.args.index("-P") + 1] = str(ctrl_port)


def _run(cfg, local_args, remote_args):
    """Start the local endpoint, and the remote one once the local one
    listens. Log the output of an endpoint that does not pass, and return
    their exit codes."""
    # Wait for each endpoint until timeout(1) has ended it, not just the 20 s
    # that bkg() waits for the local one to exit.
    wait = cfg.case_timeout + 10
    with bkg(local_args, ksft_ready=True, exit_wait=True, fail=False) as local:
        remote = cmd(shlex.join(remote_args), host=cfg.remote, fail=False,
                     timeout=wait)
        local.process(terminate=False, fail=False, timeout=wait)
    for endpoint in (local, remote):
        if endpoint.ret:
            ksft_pr(endpoint)
    return local.ret, remote.ret


def _test(cfg, case, busy_poll):
    if "UNALIGNED" in case.name and not cfg.hugepages:
        raise KsftXfailEx("no huge pages")
    if cfg.veth_test:
        _veth_xfail(cfg, case)

    ctrl_port = rand_port()
    _check_opt("-P", ctrl_port, 1, 0xffff)

    fallbacks = _setup(cfg, case, busy_poll)
    _fixup_args(cfg, case.test_id, ctrl_port)

    remote = [*cfg.remote_args,
              "-e", "tx" if case.direction == "rx" else "rx",
              *cfg.args]
    local = [*cfg.local_args,
             "-m", case.mode,
             "-e", case.direction,
             *(["-b"] if busy_poll else []),
             *cfg.args]

    local_ret, remote_ret = _run(cfg, local, remote)
    rets = {local_ret, remote_ret}
    if rets <= {0, SKIP_CODE}:
        # Both endpoints detached their XDP programs and restored the MTU.
        for fallback in fallbacks:
            fallback.cancel()
    # An endpoint that skips the case tells its peer, which skips it too.
    if SKIP_CODE in rets and rets <= {0, SKIP_CODE}:
        raise KsftSkipEx("xskxceiver skipped the case")
    ksft_eq(local_ret, 0, "local endpoint exit code")
    ksft_eq(remote_ret, 0, "remote endpoint exit code")


def test_xsk(cfg, case):
    """Run a case with the endpoints driven by interrupts."""
    _test(cfg, case, busy_poll=False)


def test_xsk_busy_poll(cfg, case):
    """Run a case with the local endpoint busy polling."""
    _test(cfg, case, busy_poll=True)


def _setup_veth(cfg):
    """Set up a run over veth, where both endpoints bind queue 0."""
    cfg.queue = 0
    cfg.case_timeout = VETH_CASE_TIMEOUT
    cfg.xsk_timeout = VETH_XSK_TIMEOUT
    try:
        with open(MAX_SKB_FRAGS, encoding="utf-8") as fp:
            cfg.max_skb_frags = int(fp.read())
    except OSError:
        cfg.max_skb_frags = DEFAULT_SKB_FRAGS
    # An skb takes a descriptor for its linear part and one per frag.
    cfg.max_frags = cfg.max_skb_frags + 1


def _setup_nic(cfg, undo):
    """Set up a run on NETIF until undo, return False if the DUT cannot run
    the cases."""
    cfg.case_timeout = NIC_CASE_TIMEOUT
    cfg.xsk_timeout = NIC_XSK_TIMEOUT
    cfg.ethnl = EthtoolFamily()
    cfg.netnl = NetdevFamily()

    dev = cfg.netnl.dev_get({"ifindex": cfg.ifindex})
    if "xsk-zerocopy" not in dev["xdp-features"]:
        print("1..0 # SKIP NIC does not advertise AF_XDP zero-copy")
        return False

    cfg.max_frags = dev.get("xdp-zc-max-segs", 1)

    # Before the DUT queue is taken out of RSS, as turning ntuple-filters on
    # can reset a NIC, and with it the RSS indirection table.
    if not (_ntuple_on(undo, cfg.ifname) and
            _ntuple_on(undo, cfg.remote_ifname, cfg.remote)):
        return False

    cfg.queue = _reserve_queue(cfg, undo)
    if cfg.queue is None:
        return False

    return (_steer_udp(cfg, undo, cfg.ifname, cfg.queue) and
            _steer_udp(cfg, undo, cfg.remote_ifname, 0, cfg.remote))


def _set_args(cfg, local_dmac, remote_dmac):
    """Set the endpoint options that the cases share. _fixup_args() sets
    those that differ between them."""
    _check_opt("--max-frags", cfg.max_frags, 1, 0xffff)
    _check_opt("--udp-port", cfg.udp_port, 1, 0xffff)
    _check_opt("--timeout", cfg.xsk_timeout, 1, 0xffff)
    _check_opt("--queue", cfg.queue, 0, 0xffffffff)

    cfg.args = ["-p", cfg.addr,
                "--max-frags", str(cfg.max_frags),
                "--udp-port", str(cfg.udp_port),
                "--timeout", str(cfg.xsk_timeout),
                "-t", "0",
                "-P", "0"]
    cfg.remote_args = ["timeout", "-k", "5", str(cfg.case_timeout),
                       str(cfg.bin_remote),
                       "-i", cfg.remote_ifname,
                       "-m", "skb",
                       "--queue", "0",
                       "--src-ip", cfg.remote_addr,
                       "--dst-ip", cfg.addr,
                       "--dst-mac", remote_dmac]
    cfg.local_args = ["timeout", "-k", "5", str(cfg.case_timeout),
                      str(cfg.bin_local),
                      "-i", cfg.ifname,
                      "--listen",
                      "--queue", str(cfg.queue),
                      "--src-ip", cfg.addr,
                      "--dst-ip", cfg.remote_addr,
                      "--dst-mac", local_dmac]


def main():
    """Run the cases over veth without NETIF, else on NETIF."""
    # defer() works only within a case, so undo restores what main() sets up
    # for all of them, however the run ends.
    with NetDrvEpEnv(__file__, veth_test=True) as cfg, \
         ExitStack() as undo:
        cfg.bin_local = cfg.net_lib_dir / "xskxceiver"
        if not cfg.bin_local.exists():
            print(f"1..0 # SKIP {cfg.bin_local} was not built")
            sys.exit(SKIP_CODE)

        # Before _setup_nic(), as ntuple-filters can reset a NIC.
        local_dmac = _next_hop_mac(cfg, cfg.remote_addr,
                                   cfg.remote_dev["address"], cfg.ifname)
        remote_dmac = _next_hop_mac(cfg, cfg.addr, cfg.dev["address"],
                                    cfg.remote_ifname, cfg.remote)

        cfg.udp_port = rand_port()
        if cfg.veth_test:
            _setup_veth(cfg)
        elif not _setup_nic(cfg, undo):
            sys.exit(SKIP_CODE)

        cfg.bin_remote = cfg.remote.deploy(cfg.bin_local)

        saved_hugepages = []
        undo.callback(_release_hugepages, saved_hugepages)
        cfg.hugepages = (_reserve_hugepages(saved_hugepages) and
                         _reserve_hugepages(saved_hugepages, cfg.remote))
        if not cfg.hugepages:
            _release_hugepages(saved_hugepages)
            saved_hugepages.clear()

        cases = _get_cases(cfg)
        _set_args(cfg, local_dmac, remote_dmac)

        tests = [ksft_variants(cases)(test_xsk)]
        if not cfg.veth_test:
            tests.append(ksft_variants(cases)(test_xsk_busy_poll))
        ksft_run(tests, args=(cfg,))
    ksft_exit()


if __name__ == "__main__":
    main()
