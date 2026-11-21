#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""HSR/PRP GRO policy, segmentation and functional ordering regressions."""
# pylint: disable=too-many-lines

from array import array
from collections import Counter
from contextlib import contextmanager
import ctypes
import errno
import json
import os
import re
import selectors
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid


class Skip(Exception):
    """A missing prerequisite for one case."""


# INT/TERM only record the signal; Lab.remaining() raises at the next check.
SIGNALLED = []

# Errors a case reports as "not ok"; anything else is a bug in this script.
CASE_ERRORS = (OSError, ValueError, RuntimeError, LookupError,
               subprocess.SubprocessError, struct.error)


def require(condition, message):
    """Raise ValueError(message) unless condition holds."""
    if not condition:
        raise ValueError(message)


def features(text):
    """Parse ethtool -k: name -> (active, fixed, requested)."""
    result = {}
    for line in text.splitlines():
        if ":" not in line or line.startswith("Features for"):
            continue
        name, state = line.strip().split(":", 1)
        match = re.fullmatch(r"\s*(on|off)((?:\s+\[[^\]]*\])*)", state)
        require(match is not None, "malformed feature line: " + line)
        # ethtool marks a wanted bit that differs from the active one.
        requested = re.search(r"\[requested (on|off)\]", match[2])
        result[name] = (match[1], "[fixed]" in match[2],
                        requested[1] if requested else match[1])
    require(result, "empty feature listing")
    return result


def decode(raw, ancillary=(), prp=False):
    """Decode one captured frame; PRP RCTs are recognized only if prp."""
    require(len(raw) >= 14, "short Ethernet capture")
    proto = struct.unpack_from("!H", raw, 12)[0]
    off, stack, aux, checksum_partial = 14, [], (), False
    for level, kind, data in ancillary:
        if level == 263 and kind == 8:
            require(len(data) >= 20, "short PACKET_AUXDATA")
            status, length, snap, _, _, tci, tpid = struct.unpack("IIIHHHH", data[:20])
            require(length == snap, "truncated packet auxiliary length")
            checksum_partial = bool(status & 8)
            if status & 0x10:
                aux = ((tpid if status & 0x40 else 0x8100, tci),)
    while proto in (0x8100, 0x88a8):
        require(off + 4 <= len(raw), "short VLAN header")
        tci, inner = struct.unpack_from("!HH", raw, off)
        stack.append((proto, tci))
        proto, off = inner, off + 4
    row = {"raw": raw, "size": len(raw) + 4 * len(aux), "vlans": aux + tuple(stack),
           "aux": aux, "inband": tuple(stack), "src": raw[6:12], "dst": raw[:6],
           "proto": proto, "seq": None, "path": None, "payload": b"", "ports": (),
           "tcpseq": None, "supervision": None, "supseq": None, "tag": False,
           "encoding": "plain", "checksum_partial": checksum_partial}
    end = len(raw)
    if proto == 0x892f:
        require(off + 6 <= end, "short HSR tag")
        field, seq, proto = struct.unpack_from("!HHH", raw, off)
        row.update(seq=seq, path=field >> 12, tag=True, encoding="hsr")
        expected = len(raw) - 14 - (4 if raw[12:14] == b"\x81\x00" else 0)
        require(field & 0xfff == expected, "HSR LSDU size differs")
        off += 6
    elif prp and end >= off + 6 and raw[-2:] == b"\x88\xfb":
        seq, field = struct.unpack_from("!HH", raw, end - 6)
        expected = len(raw) - 14 - (4 if raw[12:14] == b"\x81\x00" else 0)
        # Like prp_fill_frame_info(): a size mismatch means a plain frame.
        if field & 0xfff == expected:
            row.update(seq=seq, path=field >> 12, tag=True, encoding="prp")
            end -= 6
    row["proto"] = proto
    row["network"] = raw[off:end]
    if raw[:3] == b"\x01\x15\x4e" and proto == 0x88fb:
        require(off + 12 <= end, "short supervision payload")
        _, seq, kind, size = struct.unpack_from("!HHBB", raw, off)
        require(kind in (20, 21, 22, 23) and size in (6, 12), "invalid supervision TLV")
        row.update(supervision=raw[off + 6:off + 12], supseq=seq)
        return row
    if proto != 0x0800:
        return row
    require(off + 20 <= end and raw[off] >> 4 == 4, "invalid IPv4 header")
    ihl, total = (raw[off] & 15) * 4, struct.unpack_from("!H", raw, off + 2)[0]
    require(ihl >= 20 and total >= ihl and off + total <= end, "invalid IP extent")
    protocol, l4 = raw[off + 9], off + ihl
    ipend = off + total
    row.update(ip_src=raw[off + 12:off + 16], ip_dst=raw[off + 16:off + 20])
    if protocol == 6:
        require(l4 + 20 <= ipend, "short TCP header")
        size = (raw[l4 + 12] >> 4) * 4
        require(size >= 20 and l4 + size <= ipend, "invalid TCP extent")
        row.update(ports=struct.unpack_from("!HH", raw, l4),
                   tcpseq=struct.unpack_from("!I", raw, l4 + 4)[0],
                   tcpflags=raw[l4 + 13], payload=raw[l4 + size:ipend])
    elif protocol == 17:
        require(l4 + 8 <= ipend, "short UDP header")
        size = struct.unpack_from("!H", raw, l4 + 4)[0]
        require(size >= 8 and l4 + size == ipend, "invalid UDP extent")
        row.update(ports=struct.unpack_from("!HH", raw, l4), payload=raw[l4 + 8:ipend])
    return row


class Capture:
    """One AF_PACKET receive socket bound to a single device."""

    def __init__(self, lab, ns, dev, pkttype=None, prp=False):
        self.lab, self.rows, self.seen = lab, [], 0
        self.ns, self.dev, self.packets = ns, dev, None
        self.pkttype, self.name, self.prp = pkttype, ns + "/" + dev, prp
        self.complete, self.drops, self.truncated = False, None, 0
        self.last_seen = time.monotonic()
        # Protocol 0 registers no receive hook until bind() names the device.
        self.socket = lab.sock(ns, socket.AF_PACKET, socket.SOCK_RAW, 0)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        self.socket.setsockopt(263, 8, 1)
        self.socket.bind((dev, 3))
        self.socket.setblocking(False)
        lab.selector.register(self.socket, selectors.EVENT_READ, self)

    def drain(self):
        """Read queued frames; return (count, queue empty)."""
        count = 0
        while count < 256:
            self.lab.remaining()
            try:
                raw, anc, flags, addr = self.socket.recvmsg(131072, 256)
            except BlockingIOError:
                return count, True
            self.seen += 1
            self.last_seen = time.monotonic()
            count += 1
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                self.truncated += 1
                raise ValueError(self.name + ": capture truncated")
            if addr[0] == self.dev and (self.pkttype is None or addr[2] == self.pkttype):
                self.rows.append(decode(raw, anc, self.prp))
        return count, False

    def validate(self):
        """Fail unless the capture completed without loss."""
        require(self.complete and self.drops == 0 and self.truncated == 0,
                self.name + ": incomplete/dropped/truncated capture")


@contextmanager
def signals_blocked():
    """Hold INT/TERM back while namespace or handler state switches."""
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


class Lab:
    """Owned namespaces, sockets and captures of one test run."""

    def __init__(self, deadline):
        self.deadline = deadline
        self.names, self.sockets, self.captures, self.threads = [], [], [], []
        self.case_start = 0
        self.selector = selectors.DefaultSelector()
        self.original = os.open("/proc/self/ns/net", os.O_RDONLY)
        self.token, self.restore_failed = uuid.uuid4().hex[:10], False
        self.stop = threading.Event()
        self.libc = ctypes.CDLL(None, use_errno=True)

    def begin(self):
        """Start a case: captures left open by an earlier case are closed."""
        for cap in self.captures[self.case_start:]:
            if not cap.complete:
                self.selector.unregister(cap.socket)
                cap.socket.close()
        self.case_start = len(self.captures)

    def remaining(self):
        """Seconds left in the work deadline; raise once it or a signal hit."""
        if SIGNALLED:
            raise InterruptedError(f"signal {SIGNALLED[0]}")
        value = self.deadline - time.monotonic()
        require(value > 0, "120-second work deadline expired")
        return value

    def run(self, args, check=True):
        """Run a command with a bounded timeout."""
        require(not self.restore_failed, "network namespace restoration failed")
        result = subprocess.run([str(arg) for arg in args], text=True, capture_output=True,
                                timeout=min(5, self.remaining()), check=False)
        require(not check or result.returncode == 0,
                f"{args}: rc{result.returncode} {result.stderr.strip()}")
        return result

    def ip(self, ns, *args, check=True):
        """Run ip(8) in a namespace."""
        return self.run(["ip", "-n", ns, *args], check)

    def cmd(self, ns, *args, check=True):
        """Run a command in a namespace."""
        return self.run(["ip", "netns", "exec", ns, *args], check)

    def features(self, ns, dev):
        """Return the parsed ethtool -k listing of a device."""
        return features(self.cmd(ns, "ethtool", "-k", dev).stdout)

    def ns(self):
        """Create an owned namespace with loopback up."""
        name = f"hsrp4-{self.token}-{len(self.names)}"
        require(not os.path.lexists("/var/run/netns/" + name), "namespace collision")
        self.names.append(name)
        self.run(["ip", "netns", "add", name])
        self.ip(name, "link", "set", "dev", "lo", "up")
        return name

    def veth(self, ns, dev, peer_ns, peer):
        """Create a veth pair across two namespaces."""
        self.ip(ns, "link", "add", "name", dev, "type", "veth", "peer", "name", peer,
                "netns", peer_ns)

    def setns(self, descriptor):
        """Switch this thread's network namespace."""
        if self.libc.setns(descriptor, 0x40000000):
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))

    @contextmanager
    def enter(self, ns):
        """Run the body in a namespace and always switch back."""
        descriptor, entered = None, False
        try:
            with signals_blocked():
                descriptor = os.open("/var/run/netns/" + ns, os.O_RDONLY)
                self.setns(descriptor)
                entered = True
            yield
        finally:
            with signals_blocked():
                try:
                    if entered:
                        self.setns(self.original)
                except BaseException:
                    self.restore_failed = True
                    raise
                finally:
                    if descriptor is not None:
                        os.close(descriptor)

    def sock(self, ns, family, kind, proto=0):
        """Open an owned socket bound to a namespace."""
        with self.enter(ns):
            result = socket.socket(family, kind, proto)
            self.sockets.append(result)
        result.settimeout(min(3, self.remaining()))
        return result

    def capture(self, ns, dev, pkttype=None, prp=False):
        """Start a capture owned by the current case."""
        result = Capture(self, ns, dev, pkttype, prp)
        self.captures.append(result)
        return result

    def observe(self, seconds, pump=None):
        """Drain ready captures for some time, calling pump() each round."""
        end = time.monotonic() + seconds
        while True:
            self.remaining()
            if pump is not None:
                pump()
            for key, _ in self.selector.select(min(0.01, max(0, end - time.monotonic()))):
                key.data.drain()
            if time.monotonic() >= end:
                return

    def finish(self, done=None):
        """Complete this case's captures.

        done() states when every expected frame has been captured; the
        deadline bounds the wait. Only without such a condition does a
        100 ms quiet period end the wait.
        """
        active = [cap for cap in self.captures[self.case_start:] if not cap.complete]
        end = min(self.deadline, time.monotonic() + 2)
        quiet = time.monotonic()
        while time.monotonic() < end:
            self.observe(0.01)
            empty = True
            for cap in active:
                count, drained = cap.drain()
                if count or not drained:
                    empty = False
            quiet = max([quiet] + [cap.last_seen for cap in active])
            if done is not None:
                if done():
                    break
            elif empty and time.monotonic() - quiet >= 0.1:
                break
        else:
            # A missing expected frame is reported by the case's verifier.
            require(done is not None, "capture failed to drain within fixed deadline")
        end = max(end, min(self.deadline, time.monotonic() + 1))
        for ns in sorted({cap.ns for cap in active}):
            require(time.monotonic() < end, "capture cutoff/drain deadline expired")
            require(ns in self.names, "capture namespace is not owned")
            self.ip(ns, "link", "set", "dev", "lo", "down")
            require(time.monotonic() < end, "capture cutoff/drain deadline expired")
            state = link_state(self, ns, "lo")
            require(time.monotonic() < end, "capture cutoff/drain deadline expired")
            require("UP" not in state["flags"],
                    "capture cutoff loopback is still up")
        # Rebinding to a different down device synchronizes the old receive hook.
        # Its ENETDOWN socket error must be cleared before draining queued frames.
        for cap in active:
            require(time.monotonic() < end, "capture cutoff/drain deadline expired")
            require(cap.dev != "lo", "capture already uses the cutoff device")
            cap.socket.bind(("lo", 0))
            require(cap.socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == errno.ENETDOWN,
                    cap.name + ": capture cutoff did not report ENETDOWN")
        for cap in active:
            while True:
                require(time.monotonic() < end, "capture cutoff/drain deadline expired")
                if cap.drain()[1]:
                    break
            require(time.monotonic() < end, "capture cutoff/drain deadline expired")
            packets, cap.drops = struct.unpack("II", cap.socket.getsockopt(263, 6, 8))
            cap.packets = packets
            require(time.monotonic() < end, "capture cutoff/drain deadline expired")
            require(packets == cap.seen + cap.drops,
                    f"{cap.name}: queued capture remains packets={packets} "
                    f"seen={cap.seen} drops={cap.drops}")
            cap.complete = True
            cap.validate()
            self.selector.unregister(cap.socket)
            cap.socket.close()
            print(f"# capture {cap.name} packets={cap.seen} drops=0 truncated=0 complete=1",
                  flush=True)

    def close(self):
        """Stop threads, close sockets and delete owned namespaces."""
        self.stop.set()
        end, errors = time.monotonic() + 20, []
        for sock in self.sockets:
            sock.close()
        for thread in self.threads:
            if thread.ident is not None:
                thread.join(max(0, end - time.monotonic()))
            if thread.is_alive():
                errors.append("sender thread did not stop")
        self.selector.close()
        if self.restore_failed:
            # ip netns del removes the /var/run/netns bind mount, which does
            # not depend on the network namespace of this thread.
            errors.append("network namespace restoration failed")
        for name in reversed(self.names):
            if time.monotonic() >= end:
                errors.append("cleanup deadline expired with owned namespaces remaining")
                break
            try:
                result = subprocess.run(["ip", "netns", "del", name],
                                        capture_output=True, text=True, check=False,
                                        timeout=min(3, end - time.monotonic()))
                require(result.returncode == 0 and
                        not os.path.lexists("/var/run/netns/" + name),
                        "namespace cleanup failed: " + name + " " + result.stderr)
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                errors.append(str(error))
        os.close(self.original)
        directory = os.getenv("HSR_CAPTURE_EVIDENCE")
        if directory:
            try:
                for number, cap in enumerate(self.captures):
                    require(time.monotonic() < end, "cleanup/evidence deadline expired")
                    path = os.path.join(directory, f"{self.token}-{number}.json")
                    record = {"name": cap.name, "seen": cap.seen, "packets": cap.packets,
                              "drops": cap.drops, "truncated": cap.truncated,
                              "complete": cap.complete, "pkttype": cap.pkttype,
                              "rows": cap.rows}
                    with open(path, "x", encoding="utf-8") as stream:
                        json.dump(record, stream, default=lambda value: value.hex())
            except (OSError, ValueError, TypeError) as error:
                errors.append("capture evidence: " + str(error))
        require(not errors, "; ".join(errors))


def coverage(frames, expected):
    """Count how often each stream byte occurs in (offset, payload) frames."""
    counts = array("I", [0]) * len(expected)
    for offset, payload in frames:
        require(payload and offset >= 0 and offset + len(payload) <= len(expected),
                "invalid stream extent")
        require(payload == expected[offset:offset + len(payload)], "stream payload differs")
        for position in range(offset, offset + len(payload)):
            counts[position] += 1
    return counts


def protocol_order(rows, wrap=False, key="seq"):
    """Require strictly increasing 16-bit protocol sequence numbers."""
    numbers = [row[key] for row in rows]
    require(numbers and all(value is not None for value in numbers), "missing protocol sequence")
    # Successive pairs; itertools.pairwise() needs Python 3.10.
    steps = [(numbers[index - 1], numbers[index]) for index in range(1, len(numbers))]
    require(all(0 < ((right - left) & 0xffff) < 0x8000 for left, right in steps),
            "protocol sequence out of order")
    if wrap:
        require(any(left > right for left, right in steps), "no actual sequence wrap")


def contains(have, wanted):
    """Multiset inclusion of Counters (their >= needs Python 3.10)."""
    return all(have[key] >= count for key, count in wanted.items())


def wire_rows(rows, port, stack, tagged=True):
    """Return and check one lane's frames of a flow."""
    data = [row for row in rows if row["ports"] and row["ports"][1] == port and row["payload"]]
    require(data, "no captured flow payload")
    for row in data:
        require(row["tag"] == tagged, "flow tag/RCT missing or unexpected")
        require(row["encoding"] == ("hsr" if tagged else "plain"), "wrong protocol tag kind")
        require(row["vlans"] == stack, "flow VLAN stack differs")
        require(row["size"] <= 1520 + 4 * len(stack), "unsegmented output frame")
    require(len({row["src"] for row in data}) == 1 and
            len({row["dst"] for row in data}) == 1, "flow MAC addresses differ within lane")
    if tagged:
        protocol_order(data)
    return data


def copy_identity(row):
    """Fields the two LAN copies of a frame share."""
    # Lane/path and source substitution differ legitimately between the two ports.
    return (row["seq"], row["vlans"], row["dst"], row["proto"], row["network"])


def verify_stream(captures, port, payload, stack=(), local=False, inband=False, ingress=None):
    """Check every TCP byte occurrence on the sender against the outputs."""
    for cap in captures:
        cap.validate()
    source = [row for row in captures[0].rows if row["ports"] and
              row["ports"][1] == port and row["payload"]]
    require(source, "sender TCP capture empty")
    syn = [row for row in captures[0].rows if row["ports"] and
           row["ports"][1] == port and row.get("tcpflags", 0) & 2]
    require(syn, "missing captured TCP initial sequence")
    isn = (syn[0]["tcpseq"] + 1) & 0xffffffff
    source_counts = coverage([((row["tcpseq"] - isn) & 0xffffffff, row["payload"])
                              for row in source], payload)
    require(0 not in source_counts, "sender did not send complete stream")
    aggregate = [row for row in source if len(row["payload"]) > 1500]
    if ingress is not None:
        ingress.validate()
        inputs = [row for row in ingress.rows if row["ports"] and
                  row["ports"][1] == port and row["payload"]]
        require(all(row["vlans"] == stack and row["encoding"] == "plain" for row in inputs),
                "HSR/PRP ingress classification/VLAN differs")
        require(coverage([((row["tcpseq"] - isn) & 0xffffffff, row["payload"])
                          for row in inputs], payload) == source_counts,
                "sender/actual ingress stream occurrence differs")
        require(not aggregate or any(len(row["payload"]) > 1500 for row in inputs),
                "no actual ingress aggregate")
    require(all(row["vlans"] == stack for row in source), "sender VLAN stack differs")
    if stack:
        require(all(row["aux"] == (() if inband else stack[:1]) and
                    row["inband"] == (stack if inband else stack[1:]) for row in aggregate),
                "sender aggregate VLAN encoding differs")
    if local:
        outputs = [wire_rows(captures[1].rows, port, stack, tagged=False)]
        require(all(row["ports"][1] == port for row in outputs[0]),
                "unexpected local flow direction")
    else:
        outputs = [wire_rows(cap.rows, port, stack) for cap in captures[1:]]
        for index, rows in enumerate(outputs):
            require(all(row["path"] == index for row in rows), "wrong HSR lane/path")
        require([copy_identity(row) for row in outputs[0]] ==
                [copy_identity(row) for row in outputs[1]], "LAN copies differ")
    for rows in outputs:
        observed = coverage([((row["tcpseq"] - isn) & 0xffffffff, row["payload"])
                             for row in rows], payload)
        require(observed == source_counts,
                "lost/duplicate stream occurrence (including retransmission)")
    # Missing aggregation is a prerequisite gap only after transfer and all other checks.
    if not aggregate:
        raise Skip("no sender GSO aggregate observed")
    print(f"# TCP bytes={len(payload)} sent-occurrences={sum(source_counts)} "
          f"aggregates={len(aggregate)} outputs={[len(rows) for rows in outputs]}", flush=True)


def verify_udp(case, captures, expected, ports, vlans=(), expect_wrap=False,
               input_order=False, producer_order=False):
    """Check both lanes against the expected UDP payloads."""
    lanes = []
    for index, cap in enumerate(captures):
        cap.validate()
        rows = udp_rows(cap, ports)
        require(Counter(row["payload"] for row in rows) == Counter(expected),
                case + ": UDP payload/ID set differs")
        if input_order:
            require([row["payload"] for row in rows] == expected, case + ": input order differs")
        if producer_order:
            for producer in (1, 2):
                observed = [row["payload"] for row in rows if row["payload"][6] == producer]
                require(observed == [body for body in expected if body[6] == producer],
                        case + ": producer order differs")
        for row in rows:
            require(row["tag"] and row["size"] <= 1520 + 4 * len(vlans),
                    case + ": missing tag or unsegmented frame")
            require(row["vlans"] == vlans, case + ": VLAN stack differs")
            require(row["path"] == index, case + ": wrong HSR lane/path")
            require(row["encoding"] == "hsr", case + ": wrong protocol tag kind")
        protocol_order(rows, expect_wrap)
        lanes.append(rows)
    require([copy_identity(row) for row in lanes[0]] == [copy_identity(row) for row in lanes[1]],
            case + ": unequal LAN copies")
    print(f"# {case} expected={len(expected)} lanes={[len(rows) for rows in lanes]}",
          flush=True)
    return lanes


def local_pair(lab, ns, dev):
    """Create an up veth pair dev/devp inside one namespace."""
    lab.veth(ns, dev, ns, dev + "p")
    for name in (dev, dev + "p"):
        lab.ip(ns, "link", "set", "dev", name, "up")


def link_state(lab, ns, dev):
    """Return the ip -j -d link description of a device."""
    result = lab.ip(ns, "-j", "-d", "link", "show", "dev", dev)
    rows = json.loads(result.stdout)
    require(len(rows) == 1, f"{dev}: missing link description")
    state = rows[0]
    require(isinstance(state.get("ifindex"), int), "missing ifindex")
    require(isinstance(state.get("promiscuity"), int),
            f"{dev}: missing promiscuity count")
    return state


def gro_state(lab, ns, dev, expected, label):
    """Require software GRO to be expected, as requested and as active."""
    listing = lab.features(ns, dev)
    require("generic-receive-offload" in listing,
            f"{dev}: missing software GRO feature")
    active, _, requested = listing["generic-receive-offload"]
    require(active == expected and requested == expected,
            f"{label}: {dev}: GRO expected {expected}, "
            f"observed active {active} requested {requested}")


def set_gro(lab, ns, dev, wanted, active=None):
    """Request GRO; the read-back, not ethtool's output, is the oracle."""
    result = lab.cmd(ns, "ethtool", "-K", dev, "gro", wanted, check=False)
    # ethtool exits 1 when the kernel keeps a feature from changing.
    require(result.returncode == 0 or (active is not None and result.returncode == 1),
            f"{dev}: GRO setter rc{result.returncode} {result.stderr.strip()}")
    gro_state(lab, ns, dev, active if active is not None else wanted,
              "requested GRO " + wanted)


def interlink_unsupported(stderr):
    """True if iproute2 does not know the interlink option."""
    error = stderr.lower()
    return "interlink" in error and "rtnetlink" not in error and any(
        word in error for word in ("unknown command", "unknown option",
                                   "unknown argument", 'what is "interlink"'))


def hsr_attach(lab, ns, master, first, second, interlink=None):
    """Create an HSRv1 device over the given ports and bring it up."""
    args = ["link", "add", "name", master, "type", "hsr",
            "slave1", first, "slave2", second, "version", "1"]
    if interlink is not None:
        args.extend(("interlink", interlink))
    result = lab.ip(ns, *args, check=False)
    if result.returncode and interlink is not None:
        # Tool-option absence needs a successful ordinary-HSR control.
        control = lab.ip(ns, "link", "add", "ctl", "type", "hsr",
                         "slave1", first, "slave2", second,
                         "version", "1", check=False)
        if control.returncode == 0:
            lab.ip(ns, "link", "del", "ctl")
        require(control.returncode == 0,
                "interlink failed and ordinary HSR control failed: "
                f"{result.stderr.strip()} / {control.stderr.strip()}")
        if interlink_unsupported(result.stderr):
            raise Skip("iproute2 has no interlink option")
    require(result.returncode == 0,
            "HSR attach failed: " + result.stderr.strip())
    lab.ip(ns, "link", "set", "dev", master, "up")


def policy(lab):
    """All roles, initial preferences and last requests, twice each."""
    ns = lab.ns()
    for dev in ("m", "p", "q"):
        local_pair(lab, ns, dev)
    for role in ("A", "B", "interlink"):
        for initial in ("on", "off"):
            for last in ("on", "off"):
                label = f"{role} initial={initial} last={last}"
                before = link_state(lab, ns, "m")
                for _ in range(2):
                    set_gro(lab, ns, "m", initial)
                    first = "m" if role == "A" else "p"
                    second = "m" if role == "B" else "q"
                    hsr_attach(lab, ns, "hsr0", first, second,
                               "m" if role == "interlink" else None)
                    gro_state(lab, ns, "m", "off", label + " after attach")
                    for wanted in ("on", "off", last):
                        set_gro(lab, ns, "m", wanted, active="off")
                    lab.ip(ns, "link", "del", "hsr0")
                    after = link_state(lab, ns, "m")
                    require("master" not in after,
                            label + ": upper remains after detach")
                    require(after["promiscuity"] == before["promiscuity"],
                            label + ": promiscuity changed after detach")
                    # The request was dropped while attached and stays off.
                    gro_state(lab, ns, "m", "off", label + " after detach")
                    set_gro(lab, ns, "m", "on")
                print(f"# policy {label} cycles=2", flush=True)


def master_gso(lab):
    """The HSR master advertises no GSO types."""
    ns = lab.ns()
    for dev in ("a", "b"):
        local_pair(lab, ns, dev)
    hsr_attach(lab, ns, "hsr0", "a", "b")
    listing = lab.features(ns, "hsr0")
    names = [name for name in listing if
             ("segmentation" in name or name in
              ("tx-gso-robust", "tx-gso-partial", "tx-gso-list"))
             and name != "generic-segmentation-offload"]
    require(names, "master GSO type mask is absent from feature report")
    enabled = [name for name in names if listing[name][0] != "off"]
    require(not enabled, "master retains GSO types: " + ", ".join(enabled))
    print("# master GSO types off: " + ", ".join(sorted(names)), flush=True)


def refused_second_port(lab):
    """A refused second port (a bridge port) leaves the first port as it was."""
    ns = lab.ns()
    for dev in ("a", "b", "c"):
        local_pair(lab, ns, dev)
    for dev in ("a", "b"):
        set_gro(lab, ns, dev, "on")
    lab.ip(ns, "link", "add", "br0", "type", "bridge")
    lab.ip(ns, "link", "set", "dev", "b", "master", "br0")
    lab.ip(ns, "link", "set", "dev", "br0", "up")
    before = {dev: link_state(lab, ns, dev) for dev in ("a", "b")}
    result = lab.ip(ns, "link", "add", "hsr0", "type", "hsr",
                    "slave1", "a", "slave2", "b", "version", "1",
                    check=False)
    require(result.returncode != 0, "second-port attachment unexpectedly passed")
    require(RX_BUSY in result.stderr,
            "missing busy RX-handler refusal: " + result.stderr.strip())
    # B is refused before any state change.
    refused = link_state(lab, ns, "b")
    require(refused.get("master") == "br0" and
            refused["promiscuity"] == before["b"]["promiscuity"],
            "refused second port changed its bridge membership or promiscuity")
    gro_state(lab, ns, "b", "on", "refused second port")
    # Every port is checked before any is changed: A keeps its state.
    after = link_state(lab, ns, "a")
    require("master" not in after, "first port A gained an upper")
    require(after["promiscuity"] == before["a"]["promiscuity"],
            "first port A changed its promiscuity")
    gro_state(lab, ns, "a", "on", "first port A")
    # This positive control detects a residual role or RX handler on A.
    hsr_attach(lab, ns, "hsr1", "a", "c")
    lab.ip(ns, "link", "del", "hsr1")
    gro_state(lab, ns, "a", "off", "attach positive control")
    set_gro(lab, ns, "a", "on")
    print("# refused second port left A unchanged; attach of A passed", flush=True)


def multicast_flow(lab, ns, phase):
    """Exact multicast receipt on both lower and macvlan, with no workers."""
    captures = [lab.capture(ns, dev) for dev in ("m", "mv")]
    sender = lab.sock(ns, socket.AF_PACKET, socket.SOCK_RAW, 0)
    sender.bind(("mp", 0))
    sender.setblocking(False)
    source = bytes.fromhex(link_state(lab, ns, "mp")["address"].replace(":", ""))
    prefix = f"hsr-macvlan-{phase}:".encode()
    frames = [bytes.fromhex("01005e000009") + source + b"\x88\xb5" +
              prefix + struct.pack("!H", index) + b"m" * 96
              for index in range(50)]
    for frame in frames:
        require(sender.send(frame) == len(frame), "short multicast send")
        lab.observe(0.002)
    expected = Counter(frames)

    def copies(capture):
        return Counter(row["raw"] for row in capture.rows
                       if row["raw"][12:14] == b"\x88\xb5" and
                       row["raw"][14:].startswith(prefix))

    # finish() establishes real empty queues and valid loss/truncation stats.
    lab.finish(lambda: all(contains(copies(capture), expected) for capture in captures))
    for dev, capture in zip(("m", "mv"), captures):
        observed = copies(capture)
        require(observed == expected,
                f"{phase} {dev} multicast copies differ: "
                f"missing={sum((expected - observed).values())} "
                f"excess={sum((observed - expected).values())}")
    print(f"# macvlan {phase} multicast lower=50/50 upper=50/50", flush=True)


def kind_unavailable(stderr):
    """True if ip link add failed because the device kind is not available."""
    error = stderr.lower()
    return "unknown device type" in error or "operation not supported" in error


def rollback_macvlan(lab):
    """A non-master upper occupies the RX handler; delivery survives."""
    ns = lab.ns()
    for dev in ("m", "p"):
        local_pair(lab, ns, dev)
    result = lab.ip(ns, "link", "add", "link", "m", "name", "mv",
                    "type", "macvlan", "mode", "bridge", check=False)
    if result.returncode:
        if kind_unavailable(result.stderr):
            raise Skip("macvlan device kind unavailable: " + result.stderr.strip())
        require(False, "macvlan creation failed: " + result.stderr.strip())
    lab.ip(ns, "link", "set", "dev", "mv", "up")
    lab.ip(ns, "maddress", "add", "01:00:5e:00:00:09", "dev", "mv")
    set_gro(lab, ns, "m", "on")
    before = link_state(lab, ns, "m")
    require("master" not in before, "macvlan lower already has a master")

    def association():
        index = lab.cmd(ns, "cat", "/sys/class/net/mv/iflink").stdout.strip()
        require(index == str(link_state(lab, ns, "m")["ifindex"]),
                "macvlan no longer belongs to the original lower")
        membership = lab.ip(ns, "maddress", "show", "dev", "mv").stdout.lower()
        require("01:00:5e:00:00:09" in membership,
                "macvlan multicast membership missing")

    association()
    multicast_flow(lab, ns, "before")
    result = lab.ip(ns, "link", "add", "hsr0", "type", "hsr",
                    "slave1", "m", "slave2", "p", "version", "1",
                    check=False)
    require(result.returncode != 0 and RX_BUSY in result.stderr,
            "expected busy RX-handler refusal: " + result.stderr.strip())
    after = link_state(lab, ns, "m")
    require("master" not in after, "failed attachment left an HSR upper")
    require(after["promiscuity"] == before["promiscuity"],
            "failed attachment changed promiscuity")
    # The lower is refused before any state change and keeps its request.
    gro_state(lab, ns, "m", "on", "refused macvlan lower")
    association()
    multicast_flow(lab, ns, "after")


def member_down_up(lab):
    """Close and reopen a member attached with GRO requested."""
    ns = lab.ns()
    for dev in ("m", "p"):
        local_pair(lab, ns, dev)
    set_gro(lab, ns, "m", "on")
    hsr_attach(lab, ns, "hsr0", "m", "p")
    gro_state(lab, ns, "m", "off", "attached member")
    # Each command must return within the bound of Lab.run().
    lab.ip(ns, "link", "set", "dev", "m", "down")
    lab.ip(ns, "link", "set", "dev", "m", "up")
    lab.ip(ns, "link", "del", "hsr0")
    gro_state(lab, ns, "m", "off", "detached member")
    set_gro(lab, ns, "m", "on")
    print("# attached member down/up returned; GRO re-enabled after detach", flush=True)


def attach_down_up_detach(lab):
    """Attach a down member with GRO requested, open it, detach while up."""
    ns = lab.ns()
    for dev in ("m", "p"):
        local_pair(lab, ns, dev)
    lab.ip(ns, "link", "set", "dev", "m", "down")
    set_gro(lab, ns, "m", "on")
    hsr_attach(lab, ns, "hsr0", "m", "p")
    gro_state(lab, ns, "m", "off", "attached down member")
    lab.ip(ns, "link", "set", "dev", "m", "up")
    lab.ip(ns, "link", "del", "hsr0")
    gro_state(lab, ns, "m", "off", "member detached while up")
    lab.ip(ns, "link", "set", "dev", "m", "down")
    lab.ip(ns, "link", "set", "dev", "m", "up")
    set_gro(lab, ns, "m", "on")
    print("# down member attached, opened, detached up; GRO re-enabled", flush=True)


def request_while_attached(lab):
    """A GRO request on an attached member is dropped, also after detach."""
    ns = lab.ns()
    for dev in ("m", "p"):
        local_pair(lab, ns, dev)
    set_gro(lab, ns, "m", "off")
    hsr_attach(lab, ns, "hsr0", "m", "p")
    set_gro(lab, ns, "m", "on", active="off")
    lab.ip(ns, "link", "del", "hsr0")
    gro_state(lab, ns, "m", "off", "member after detach")
    print("# GRO request while attached dropped; stays off after detach", flush=True)


PORT_ERROR = "Cannot use a bridge, bond, team or OVS master as HSR port"
STACKED_ERROR = "Cannot use a macvlan or MACsec device stacked on"
MACVLAN_GRO = "macvlan inherits GRO from its lower device"
MASTER_ERROR = "Device already has a master"
RX_BUSY = "RX handler busy"
NO_RX_HANDLER = "does not support an RX handler"


def port_types(lab):
    """Forwarding masters, macvlans on them, devices with a master and a
    macvlan whose lower runs GRO are refused before any port changes; a
    macvlan on a veth without GRO is accepted."""
    ns = lab.ns()
    for dev in ("p", "q", "l", "s"):
        local_pair(lab, ns, dev)
    # A macvlan takes the RX handler of its lower: it gets its own bridge.
    for bridge in ("br0", "br1"):
        lab.ip(ns, "link", "add", bridge, "type", "bridge")
    candidates, refused, skipped = [("bridge", "br0", PORT_ERROR)], [], []
    for kind, dev, lower, args, error in (
            ("bond", "bond0", None, ("bond0", "type", "bond"), PORT_ERROR),
            ("macvlan on a bridge", "mvb", None,
             ("link", "br1", "name", "mvb", "type", "macvlan", "mode", "bridge"), STACKED_ERROR),
            # Its own bond, as br1 for the macvlan on a bridge.
            ("macvlan on a bond", "mvo", ("bond1", "type", "bond"),
             ("link", "bond1", "name", "mvo", "type", "macvlan", "mode", "bridge"), STACKED_ERROR),
            ("ipvlan", "ipv0", None, ("link", "s", "name", "ipv0", "type", "ipvlan",
                                      "mode", "l2"), NO_RX_HANDLER)):
        result = lab.ip(ns, "link", "add", *lower, check=False) if lower else None
        if result is None or not result.returncode:
            result = lab.ip(ns, "link", "add", *args, check=False)
        if not result.returncode:
            candidates.append((kind, dev, error))
        elif kind_unavailable(result.stderr):
            skipped.append(f"{kind} device kind unavailable")
        else:
            require(False, f"{kind} creation failed: {result.stderr.strip()}")
    before = {dev: link_state(lab, ns, dev)
              for dev in ("p", "q", *(dev for _, dev, _ in candidates))}
    for kind, dev, error in candidates:
        for role, ports in (("slave1", ("slave1", dev, "slave2", "p")),
                            ("slave2", ("slave1", "p", "slave2", dev)),
                            ("interlink", ("slave1", "p", "slave2", "q", "interlink", dev))):
            label = f"{kind} as {role}"
            result = lab.ip(ns, "link", "add", "name", "hsr0", "type", "hsr", *ports,
                            "version", "1", check=False)
            require(result.returncode != 0, label + ": accepted")
            if role == "interlink" and interlink_unsupported(result.stderr):
                skipped.append(label + ": iproute2 has no interlink option")
                continue
            require(error in result.stderr,
                    f"{label}: missing refusal message: {result.stderr.strip()}")
            require(lab.ip(ns, "link", "show", "dev", "hsr0", check=False).returncode,
                    label + ": HSR device left behind")
            for name, state in before.items():
                after = link_state(lab, ns, name)
                require("master" not in after and
                        after["promiscuity"] == state["promiscuity"],
                        f"{label}: {name} changed by the refused attach")
            refused.append(label)
    # A refused second port leaves the first port as it was.
    for dev in ("w", "g"):
        local_pair(lab, ns, dev)
    set_gro(lab, ns, "p", "on")
    set_gro(lab, ns, "g", "on")
    first, second = link_state(lab, ns, "p"), []
    for kind, dev, args, error, setup in (
            ("VRF port", "w", ("vrf0", "type", "vrf", "table", "10"), MASTER_ERROR,
             ("link", "set", "dev", "w", "master", "vrf0")),
            ("macvlan whose lower runs GRO", "mvg",
             ("link", "g", "name", "mvg", "type", "macvlan", "mode", "bridge"), MACVLAN_GRO,
             None)):
        kind_name = "vrf" if dev == "w" else "macvlan"
        result = lab.ip(ns, "link", "add", *args, check=False)
        if not result.returncode:
            if setup:
                lab.ip(ns, *setup)
            second.append((kind, dev, error))
        elif kind_unavailable(result.stderr):
            skipped.append(f"{kind_name} device kind unavailable")
        else:
            require(False, f"{kind_name} creation failed: {result.stderr.strip()}")
    for kind, dev, error in second:
        label = f"{kind} as slave2"
        state = link_state(lab, ns, dev)
        result = lab.ip(ns, "link", "add", "name", "hsr0", "type", "hsr",
                        "slave1", "p", "slave2", dev, "version", "1", check=False)
        require(result.returncode != 0 and error in result.stderr,
                f"{label}: missing refusal message: {result.stderr.strip()}")
        require(lab.ip(ns, "link", "show", "dev", "hsr0", check=False).returncode,
                label + ": HSR device left behind")
        after = link_state(lab, ns, "p")
        require("master" not in after and after["promiscuity"] == first["promiscuity"],
                f"{label}: first port p changed by the refused attach")
        after = link_state(lab, ns, dev)
        require(after.get("master") == state.get("master") and
                after["promiscuity"] == state["promiscuity"],
                f"{label}: {dev} changed by the refused attach")
        gro_state(lab, ns, "p", "on", label + ": first port p")
        refused.append(label)
    print("# refused: " + ", ".join(refused), flush=True)
    # A macvlan on a veth without GRO is a valid port (positive control).
    set_gro(lab, ns, "l", "off")
    result = lab.ip(ns, "link", "add", "link", "l", "name", "mv0", "type", "macvlan",
                    "mode", "bridge", check=False)
    if not result.returncode:
        lab.ip(ns, "link", "set", "dev", "mv0", "up")
        hsr_attach(lab, ns, "hsr0", "mv0", "p")
        lab.ip(ns, "link", "del", "hsr0")
        print("# accepted: macvlan on veth as slave1", flush=True)
    elif kind_unavailable(result.stderr):
        skipped.append("macvlan device kind unavailable")
    else:
        require(False, "macvlan creation failed: " + result.stderr.strip())
    if skipped:
        raise Skip("; ".join(skipped) + "; refused: " + ", ".join(refused))


GSO_ROWS = (
    ("plain", (), False, "A"),
    ("s-tag-inband", ((0x88a8, 100),), True, "A"),
    ("c-tag-accelerated", ((0x8100, 50),), False, "A"),
    ("s-tag-accelerated", ((0x88a8, 100),), False, "B"),
    ("sc-nested-accelerated", ((0x88a8, 200), (0x8100, 30)), False, "B"),
    ("cc-nested-inband", ((0x8100, 40), (0x8100, 20)), True, "A"),
)


def vlan_chain(lab, ns, parent, stack, prefix):
    """Stack VLAN devices on parent; return the innermost one."""
    for depth, (protocol, identifier) in enumerate(stack):
        dev = f"{prefix}{depth}"
        lab.ip(ns, "link", "add", "link", parent, "name", dev,
               "type", "vlan", "id", str(identifier), "protocol",
               "802.1AD" if protocol == 0x88a8 else "802.1Q")
        lab.ip(ns, "link", "set", "dev", dev, "up")
        parent = dev
    return parent


def vlan_tx_mode(lab, ns, lower, stack, inband):
    """Select accelerated or in-band insertion of the outer VLAN tag."""
    if not stack:
        return
    aliases = (("tx-vlan-stag-hw-insert", "tx-vlan-stag-offload")
               if stack[0][0] == 0x88a8 else
               ("tx-vlan-offload", "tx-vlan-hw-insert"))
    listing = lab.features(ns, lower)
    name = next((alias for alias in aliases if alias in listing), None)
    if name is None:
        raise Skip("no VLAN insertion feature: " + ", ".join(aliases))
    wanted = "off" if inband else "on"
    if listing[name][1] and listing[name][0] != wanted:
        raise Skip("fixed VLAN insertion feature cannot be " + wanted)
    lab.cmd(ns, "ethtool", "-K", lower, name, wanted)
    require(lab.features(ns, lower)[name][0] == wanted,
            "VLAN insertion mode did not match its requested state")


def ordered_payload(producer, index, size=64):
    """Payload naming its producer and index."""
    prefix = b"HSRORD" + bytes([producer]) + struct.pack("!I", index)
    return prefix + bytes([producer ^ 0xA5]) * (size - len(prefix))


def ordered_socket(lab, ns, address):
    """UDP multicast sender bound to address."""
    sock = lab.sock(ns, socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((address, 0))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    sock.settimeout(1)
    return sock


def ordered_lanes(lab, topology):
    """Capture the frames the DUT transmits on its two LAN ports."""
    return [lab.capture(topology["dut"], lane, pkttype=4)
            for lane in ("da", "db")]


def ordered_send(lab, sock, producer, first, count, port, segment=0):
    """Send count datagrams, or UDP GSO aggregates of 16; return the payloads."""
    expected = []
    if segment:
        sock.setsockopt(socket.IPPROTO_UDP, 103, segment)
    blocks = 16 if segment else 1
    size = segment or 64
    for number in range(count):
        payloads = [ordered_payload(producer, first + number * blocks + n,
                                    size) for n in range(blocks)]
        body = b"".join(payloads)
        require(sock.sendto(body, ("239.0.0.9", port)) == len(body),
                "short UDP send")
        expected.extend(payloads)
        # Keep capture receive queues bounded throughout long wrap warmups.
        if number % 8 == 0:
            lab.observe(0)
    lab.observe(0.1)
    return expected


def udp_rows(cap, ports):
    """Captured UDP frames addressed to one of ports."""
    return [row for row in cap.rows if row["ports"] and row["ports"][1] in ports]


def lanes_hold(caps, expected, ports):
    """Completion condition: every lane captured each expected payload."""
    wanted = Counter(expected)
    return lambda: all(contains(Counter(row["payload"] for row in udp_rows(cap, ports)), wanted)
                       for cap in caps)


def ordered_data(lab, gso=False):
    """Local data around interlink data or aggregates keeps its order."""
    topology = topo(lab)
    caps = ordered_lanes(lab, topology)
    local = ordered_socket(lab, topology["dut"], "100.64.3.1")
    san = ordered_socket(lab, topology["tx"], "100.64.2.1")
    # Observe interlink aggregates before the two tagged LAN copies expand.
    sent = lab.capture(topology["tx"], "t0", pkttype=4)
    ingress = lab.capture(topology["dut"], "dil")
    expected = ordered_send(lab, local, 1, 0, 32, 5100)
    expected += ordered_send(lab, san, 2, 0, 16, 5101, segment=512 if gso else 0)
    expected += ordered_send(lab, local, 1, 32, 32, 5100)
    lanes_done = lanes_hold(caps, expected, {5100, 5101})
    lab.finish(lambda: lanes_done() and
               len(udp_rows(ingress, {5101})) >= len(udp_rows(sent, {5101})) > 0)
    verify_udp("local and aggregate boundaries", caps, expected,
               ports={5100, 5101}, input_order=True)
    inputs = udp_rows(sent, {5101})
    if gso:
        expected_inputs = [b"".join(ordered_payload(2, n * 16 + part, 512)
                                    for part in range(16)) for n in range(16)]
    else:
        expected_inputs = expected[32:48]
    aggregated = any(len(row["payload"]) > 1500 for row in inputs)
    if gso and not aggregated:
        expected_inputs = expected[32:-32]
    require([row["payload"] for row in inputs] == expected_inputs,
            "UDP sender input set/order differs")
    incoming = udp_rows(ingress, {5101})
    require([row["payload"] for row in incoming] == expected_inputs,
            "actual UDP ingress input set/order differs")
    require(all(row["encoding"] == "plain" and not row["vlans"] for row in inputs + incoming),
            "UDP input classification/VLAN differs")
    if gso and not aggregated:
        raise Skip("interlink UDP GSO aggregate not observed")


def ordered_supervision(lab):
    """Local and proxy supervision frames are numbered with the data."""
    topology = topo(lab)
    caps = ordered_lanes(lab, topology)
    san = ordered_socket(lab, topology["tx"], "100.64.2.1")
    expected = ordered_send(lab, san, 3, 0, 8, 5110)
    # Both timers have time for multiple life checks; no fake worker state.
    lab.observe(10)
    data_done = lanes_hold(caps, expected, {5110})
    macs = (topology["mac_master"], topology["mac_tx"])
    lab.finish(lambda: data_done() and all(
        sum(row["supervision"] == mac for row in cap.rows) >= 2
        for cap in caps for mac in macs))
    verify_udp("proxy-learning inputs", caps, expected, ports={5110},
               input_order=True)
    verify_supervision(caps, topology["mac_master"], topology["mac_tx"], {5110})


def ordered_concurrent(lab):
    """Master and interlink producers on two CPUs keep per-producer order."""
    cpus = sorted(os.sched_getaffinity(0))[:2]
    if len(cpus) != 2:
        raise Skip("two functional producers need two allowed CPUs")
    topology = topo(lab)
    caps = ordered_lanes(lab, topology)
    sockets = [ordered_socket(lab, topology["tx"], "100.64.2.1"),
               ordered_socket(lab, topology["dut"], "100.64.3.1")]
    barrier = threading.Barrier(3)
    stop = threading.Event()
    errors = []
    windows = [(), ()]
    until = min(lab.deadline, time.monotonic() + 15)

    def producer(index):
        try:
            # Socket namespace binding was completed before threads existed.
            os.sched_setaffinity(0, {cpus[index]})
            barrier.wait(timeout=2)
            start = time.monotonic()
            for number in range(128):
                require(not stop.is_set() and not lab.stop.is_set() and
                        time.monotonic() < until, "producer work deadline")
                body = ordered_payload(index + 1, number)
                require(sockets[index].sendto(body, ("239.0.0.9", 5120 + index)) == len(body),
                        "short producer send")
                time.sleep(0.001)
            windows[index] = (start, time.monotonic())
        except (OSError, ValueError, RuntimeError) as error:
            errors.append(error)
            stop.set()
            barrier.abort()

    threads = [threading.Thread(target=producer, args=(index,))
               for index in range(2)]
    unfinished = []
    try:
        for thread in threads:
            lab.threads.append(thread)
            thread.start()
        try:
            barrier.wait(timeout=2)
        except threading.BrokenBarrierError:
            # A producer that failed broke the barrier: report its error.
            if errors:
                raise errors[0] from None
            raise
        while any(thread.is_alive() for thread in threads):
            require(time.monotonic() < until, "producer join deadline")
            lab.observe(0.01)
    finally:
        stop.set()
        barrier.abort()
        join_end = min(lab.deadline, time.monotonic() + 2)
        for thread in threads:
            if thread.ident is not None:
                thread.join(max(0, join_end - time.monotonic()))
        unfinished = [thread for thread in threads if thread.is_alive()]
        if unfinished:
            print("# cleanup failure: sender thread remained alive")
    if errors:
        raise errors[0]
    require(not unfinished, "sender thread remained alive")
    require(all(windows) and windows[0][0] < windows[1][1] and
            windows[1][0] < windows[0][1], "producer send windows do not overlap")
    print(f"# functional producers CPUs={cpus} windows={windows}")
    expected = [ordered_payload(producer, number)
                for producer in (1, 2) for number in range(128)]
    lab.finish(lanes_hold(caps, expected, {5120, 5121}))
    verify_udp("concurrent master/interlink inputs", caps, expected,
               ports={5120, 5121}, producer_order=True)


def ordered_wrap(lab):
    """The interlink sequence number wraps with both lanes intact."""
    topology = topo(lab)
    caps = ordered_lanes(lab, topology)
    sender = ordered_socket(lab, topology["tx"], "100.64.2.1")
    probe = ordered_send(lab, sender, 4, 0, 1, 5130)
    # Wait until both lanes hold the probe; a missing copy still fails below.
    end = time.monotonic() + 5
    while not all(udp_rows(cap, {5130}) for cap in caps) and time.monotonic() < end:
        lab.observe(0.01)
    # This only selects the warmup count; final loss-free captures certify it.
    rows = [udp_rows(cap, {5130}) for cap in caps]
    require(all(len(lane) == 1 for lane in rows) and
            rows[0][0]["seq"] == rows[1][0]["seq"], "wrap probe missing or unequal")
    start = rows[0][0]["seq"]
    warm_count = (65400 - ((start + 1) & 0xFFFF)) & 0xFFFF
    warm = ordered_send(lab, sender, 5, 0, warm_count, 5131)
    # Separate IDs/ports prevent sequence-space reuse from hiding a loss.
    expected = ordered_send(lab, sender, 6, 0, 256, 5132)
    lab.finish(lanes_hold(caps, probe + warm + expected, {5130, 5131, 5132}))
    verify_udp("wrap start", caps, probe, ports={5130}, input_order=True)
    if warm:
        verify_udp("wrap warmup", caps, warm, ports={5131}, input_order=True)
    verify_udp("actual protocol wrap", caps, expected, ports={5132},
               expect_wrap=True, input_order=True)


ORDERED_CASES = (("local-data-order", ordered_data),
                 ("local-data-aggregate-boundaries", lambda lab: ordered_data(lab, True)),
                 ("local-proxy-supervision", ordered_supervision),
                 ("two-functional-producers", ordered_concurrent),
                 ("actual-sequence-wrap", ordered_wrap))


def topo(lab):
    """SAN - interlink - HSR DUT - two LANs - receiver namespaces."""
    tx, dut, rx = lab.ns(), lab.ns(), lab.ns()
    for ns, dev, peer_ns, peer in ((tx, "t0", dut, "dil"),
                                   (dut, "da", rx, "ra"), (dut, "db", rx, "rb")):
        lab.veth(ns, dev, peer_ns, peer)
        for owner, link in ((ns, dev), (peer_ns, peer)):
            lab.ip(owner, "link", "set", "dev", link, "up")
    hsr_attach(lab, dut, "hm", "da", "db", "dil")
    attributes = link_state(lab, dut, "hm")["linkinfo"]["info_data"]
    # Some iproute2 versions do not print the HSR version; check it if present.
    require(attributes.get("proto") == 0 and attributes.get("version", 1) == 1 and
            all(attributes.get(key) == value for key, value in
                (("slave1", "da"), ("slave2", "db"), ("interlink", "dil"))),
            "HSR topology has unexpected protocol/version")
    lab.ip(tx, "addr", "add", "100.64.2.1/24", "dev", "t0")
    lab.ip(dut, "addr", "add", "100.64.3.1/24", "dev", "hm")
    for ns, dev in ((tx, "t0"), (dut, "hm")):
        lab.ip(ns, "route", "add", "239.0.0.0/8", "dev", dev)
    return {"tx": tx, "dut": dut, "rx": rx, "master": "hm",
            "mac_master": bytes.fromhex(link_state(lab, dut, "hm")["address"].replace(":", "")),
            "mac_tx": bytes.fromhex(link_state(lab, tx, "t0")["address"].replace(":", ""))}


def drop_capture_head(lanes, what):
    """Drop up to two leading supervision frames that only one lane captured."""
    for this, other in ((0, 1), (1, 0)):
        if lanes[this] and lanes[other]:
            ids = [copy_identity(row) for row in lanes[this][:3]]
            first = copy_identity(lanes[other][0])
            if first in ids:
                head = ids.index(first)
                require(all(row["supervision"] is not None for row in lanes[this][:head]),
                        what + " LAN copies differ before the capture start")
                lanes[this] = lanes[this][head:]


def verify_supervision(captures, master, proxy, ports):
    """Check local and proxy supervision TLVs and their order on both lanes."""
    tagged, observed = [], []
    for lane, cap in enumerate(captures):
        cap.validate()
        frames = [row for row in cap.rows if row["encoding"] == "hsr"]
        protocol_order(frames)
        # Only this case's frames are compared between the lanes; the
        # namespaces also send IPv6 neighbor discovery and MLD frames.
        tagged.append([row for row in frames if row["supervision"] is not None or
                       (row["ports"] and row["ports"][1] in ports)])
        rows = [row for row in cap.rows if row["supervision"] is not None]
        require(all(row["encoding"] == "hsr" and row["path"] == lane for row in rows),
                "wrong supervision tag kind/path")
        require(all(row["supervision"] in (master, proxy) for row in rows),
                "unexpected supervised MAC")
        for mac in (master, proxy):
            group = [row for row in rows if row["supervision"] == mac]
            require(len(group) >= 2, "missing repeated local/proxy supervision TLV")
            protocol_order(group, key="supseq")
        protocol_order(rows)
        observed.append(rows)
    # The two lanes are captured and cut off one after the other while
    # supervision goes on: a lane may start and end in extra supervision;
    # the rest must match.
    for lanes, what in ((observed, "supervision"), (tagged, "data/supervision")):
        drop_capture_head(lanes, what)
        common = min(len(rows) for rows in lanes)
        require([copy_identity(row) for row in lanes[0][:common]] ==
                [copy_identity(row) for row in lanes[1][:common]],
                what + " LAN order differs")
        # The lanes are cut off one synchronize_net() apart. In that window
        # the two supervision sources (the local node and the proxied SAN),
        # each sending every two seconds, add at most one frame each.
        tail = [row for rows in lanes for row in rows[common:]]
        require(len(tail) <= 2 and all(row["supervision"] is not None for row in tail),
                what + " LAN copies differ beyond the capture cutoff")
    print(f"# supervision exact local/proxy TLV sets lanes={[len(rows) for rows in observed]}",
          flush=True)


def tcp_transfer(lab, sender_ns, receiver_ns, dev, source, destination, port):
    """Send a stream and a reply; the caller completes its captures."""
    payload = bytes(range(256)) * 512
    reply = b"HSR-TCP-REPLY"
    listener = lab.sock(receiver_ns, socket.AF_INET, socket.SOCK_STREAM)
    listener.bind((destination, port))
    listener.listen(1)
    client = lab.sock(sender_ns, socket.AF_INET, socket.SOCK_STREAM)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, dev.encode() + b"\0")
    client.bind((source, 0))
    client.connect((destination, port))
    server, _ = listener.accept()
    lab.sockets.append(server)
    for sock in (client, server):
        sock.setblocking(False)
    sent, received, echoed = 0, bytearray(), bytearray()
    state = {"reply": False, "write_closed": False}
    end = min(lab.deadline, time.monotonic() + 12)

    def pump():
        nonlocal sent
        if sent < len(payload):
            try:
                sent += client.send(payload[sent:sent + 65536])
            except BlockingIOError:
                pass
        elif not state["write_closed"]:
            client.shutdown(socket.SHUT_WR)
            state["write_closed"] = True
        try:
            data = server.recv(65536)
            received.extend(data)
        except BlockingIOError:
            pass
        if len(received) == len(payload) and not state["reply"]:
            require(server.send(reply) == len(reply), "short TCP reply")
            state["reply"] = True
        try:
            echoed.extend(client.recv(65536))
        except BlockingIOError:
            pass

    while len(echoed) < len(reply) and time.monotonic() < end:
        lab.observe(0.01, pump)
    require(bytes(received) == payload and bytes(echoed) == reply,
            "TCP application did not receive complete expected bytes")
    for sock in (server, client, listener):
        sock.close()
    return payload, reply


def fin_seen(caps, port):
    """Completion condition: each capture saw a FIN of the connection."""
    return lambda: all(any(port in row["ports"] and row.get("tcpflags", 0) & 1
                           for row in cap.rows) for cap in caps)


def tcp_interlink(lab):
    """A natural TCP stream from the interlink reaches both LANs intact."""
    topology = topo(lab)
    tx, dut, rx = (topology[key] for key in ("tx", "dut", "rx"))
    lab.ip(rx, "link", "add", "hr", "type", "hsr",
           "slave1", "ra", "slave2", "rb", "version", "1")
    lab.ip(rx, "link", "set", "dev", "hr", "up")
    lab.ip(tx, "addr", "add", "10.67.0.2/24", "dev", "t0")
    lab.ip(rx, "addr", "add", "10.67.0.3/24", "dev", "hr")
    lab.cmd(tx, "ethtool", "-K", "t0", "tso", "on", "gso", "on")
    caps = [lab.capture(tx, "t0", pkttype=4)] + ordered_lanes(lab, topology)
    ingress = lab.capture(dut, "dil")
    payload, _ = tcp_transfer(lab, tx, rx, "t0", "10.67.0.2", "10.67.0.3", 5200)
    lab.finish(fin_seen(caps + [ingress], 5200))
    verify_stream(caps, 5200, payload, ingress=ingress)


def tcp_prp(lab, row):
    """TCP GSO from a SAN on one PRP LAN is delivered locally, segmented."""
    name, stack, inband, side = row
    tx, dut = lab.ns(), lab.ns()
    for lane in ("a", "b"):
        lab.veth(tx, "t" + lane, dut, "d" + lane)
        lab.ip(tx, "link", "set", "dev", "t" + lane, "up")
        lab.ip(dut, "link", "set", "dev", "d" + lane, "up")
    lab.ip(dut, "link", "add", "pm", "type", "hsr", "slave1", "da", "slave2", "db", "proto", "1")
    lab.ip(dut, "link", "set", "dev", "pm", "up")
    attributes = link_state(lab, dut, "pm")["linkinfo"]["info_data"]
    require(attributes.get("proto") == 1 and
            attributes.get("slave1") == "da" and attributes.get("slave2") == "db",
            "PRP topology has unexpected protocol/ports")
    lower = "t" + side.lower()
    sender = vlan_chain(lab, tx, lower, stack, "txv")
    receiver = vlan_chain(lab, dut, "pm", stack, "rxv")
    lab.ip(tx, "addr", "add", "10.68.0.2/24", "dev", sender)
    lab.ip(dut, "addr", "add", "10.68.0.1/24", "dev", receiver)
    vlan_tx_mode(lab, tx, lower, stack, inband)
    lab.cmd(tx, "ethtool", "-K", lower, "tso", "on", "gso", "on")
    caps = [lab.capture(tx, lower, pkttype=4), lab.capture(dut, "pm", pkttype=0, prp=True)]
    ingress = lab.capture(dut, "d" + side.lower(), prp=True)
    lanes = [lab.capture(dut, dev, pkttype=4, prp=True) for dev in ("da", "db")]
    payload, reply = tcp_transfer(lab, tx, dut, sender, "10.68.0.2", "10.68.0.1", 5201)
    lab.finish(fin_seen(caps + lanes + [ingress], 5201))
    skipped = None
    try:
        verify_stream(caps, 5201, payload, stack, local=True, inband=inband, ingress=ingress)
    except Skip as error:
        # The reply checks do not depend on sender aggregation.
        skipped = error
    copies = []
    for index, cap in enumerate(lanes):
        cap.validate()
        rows = [frame for frame in cap.rows if frame["ports"] and
                frame["ports"][0] == 5201 and frame["payload"]]
        require(len(rows) == 1 and rows[0]["payload"] == reply,
                "PRP reply not exactly once per LAN")
        require(rows[0]["tag"] and rows[0]["vlans"] == stack and
                rows[0]["size"] <= 1520 + 4 * len(stack), "invalid PRP reply tag/size/VLAN")
        require(rows[0]["path"] == 10 + index, "wrong PRP LAN identifier")
        require(rows[0]["encoding"] == "prp", "wrong PRP reply tag kind")
        copies.append(copy_identity(rows[0]))
    require(copies[0] == copies[1], "PRP reply LAN copies differ")
    if skipped:
        raise skipped
    print(f"# PRP LAN {name} local data segmented; reply each LAN=1/1", flush=True)


def interrupt(signum, _frame):
    """INT/TERM handler: record the signal for Lab.remaining()."""
    SIGNALLED.append(signum)


def main():
    """Run the gro or ordered cases as TAP."""
    mode = sys.argv[1] if len(sys.argv) == 2 else ""
    require(mode in ("gro", "ordered"), "usage: hsr_gro_superpacket.py gro|ordered")
    cases = [("GRO policy", policy), ("master GSO mask", master_gso),
             ("refused second port", refused_second_port),
             ("busy-handler rollback", rollback_macvlan),
             ("member down/up while attached", member_down_up),
             ("attach down, up, detach while up", attach_down_up_detach),
             ("GRO request while attached", request_while_attached),
             ("port type rejection", port_types),
             ("natural TCP interlink", tcp_interlink)]
    cases += [("PRP LAN " + row[0], lambda lab, row=row: tcp_prp(lab, row)) for row in GSO_ROWS]
    if mode == "ordered":
        cases = ORDERED_CASES
    print(f"TAP version 13\n1..{len(cases)}", flush=True)
    missing = [tool for tool in ("ip", "ethtool") if shutil.which(tool) is None]
    if os.geteuid() or missing:
        for number, (name, _) in enumerate(cases, 1):
            print(f"ok {number} - {name} # SKIP need root/ip/ethtool {missing}", flush=True)
        return 4
    with signals_blocked():
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, interrupt)
    lab = Lab(time.monotonic() + 120)
    failure, passed = None, 0
    try:
        for number, (name, function) in enumerate(cases, 1):
            try:
                lab.begin()
                function(lab)
            except Skip as error:
                print(f"ok {number} - {name} # SKIP {error}", flush=True)
                continue
            except CASE_ERRORS as error:
                failure = error
                print(f"not ok {number} - {name}: {error}", flush=True)
                for later, (other, _) in enumerate(cases[number:], number + 1):
                    print(f"not ok {later} - {other}: stopped after prior failure", flush=True)
                break
            print(f"ok {number} - {name}", flush=True)
            passed += 1
    finally:
        with signals_blocked():
            for sig in (signal.SIGINT, signal.SIGTERM):
                signal.signal(sig, signal.SIG_IGN)
            try:
                lab.close()
            except CASE_ERRORS as error:
                print("# cleanup failure: " + str(error), flush=True)
                failure = failure or error
    return 1 if failure is not None else (0 if passed else 4)


if __name__ == "__main__":
    raise SystemExit(main())
