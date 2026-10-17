#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

"""Check that a device's advertised XDP features match its behavior."""

import ipaddress
from pathlib import Path
import re
import shlex

from lib.py import bkg, cmd, ip, ksft_eq, ksft_exit, ksft_run, NetDrvEpEnv
from lib.py import KsftFailEx, KsftSkipEx


ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
RESULT = re.compile(
    r"Feature .*: \[(NOT )?DETECTED\]\[(NOT )?ADVERTISED\]"
)


def mapped_address(address):
    """Return an IPv6 or IPv4-mapped IPv6 address for xdp_features."""
    address = ipaddress.ip_address(address)
    if address.version == 4:
        return f"::ffff:{address}"
    return str(address)


def feature_command(binary, feature, dut_addr, tester_addr, ifname,
                    tester=False):
    """Build the helper command with the configured endpoint addresses."""
    args = [str(binary)]
    if tester:
        args.append("-t")
    args += ["-f", feature, "-D", dut_addr]
    if tester:
        args += ["-C", dut_addr]
    args += ["-T", tester_addr, ifname]
    return shlex.join(args)


def run_feature(cfg, feature, ipver):
    """Run one feature with bounded helper lifetimes and verify its result."""
    cfg.require_cmd("timeout", local=False, remote=True)
    probe = cmd(shlex.join([str(cfg.xdp_features), "-q", cfg.ifname]),
                fail=False)
    if probe.ret == 4:
        raise KsftSkipEx(f"{cfg.ifname} does not advertise native XDP")
    if probe.ret:
        raise KsftFailEx(f"Unable to query XDP support: {probe}")
    if feature == "XDP_TX":
        link = ip(f"-d link show dev {cfg.ifname}", json=True)[0]
        if link.get("linkinfo", {}).get("info_kind") == "veth":
            peer = ip(f"-d link show dev {cfg.remote_ifname}", json=True,
                      host=cfg.remote)[0]
            # veth_xdp_flush() only schedules a peer with native XDP.
            if peer.get("xdp", {}).get("mode") != 1:
                raise KsftSkipEx("veth XDP_TX needs an existing peer native "
                                 "XDP program to flush its receive ring")
    if not cfg.addr_v[ipver]:
        ipver = "4" if ipver == "6" else "6"
    cfg.require_ipver(ipver)
    dut_addr = mapped_address(cfg.addr_v[ipver])
    tester_addr = mapped_address(cfg.remote_addr_v[ipver])

    dut_cmd = feature_command(cfg.xdp_features, feature, dut_addr,
                              tester_addr, cfg.ifname)
    tester_cmd = feature_command(cfg.remote_xdp_features, feature, dut_addr,
                                 tester_addr, cfg.remote_ifname, tester=True)

    with bkg(dut_cmd, exit_wait=True, ksft_ready=True):
        # Bound the remote process itself, not just the local SSH wait.
        result = cmd(f"timeout --signal=TERM --kill-after=5 90 {tester_cmd}",
                     host=cfg.remote, timeout=100)

    output = ANSI_ESCAPE.sub("", result.stdout)
    match = RESULT.search(output)
    if not match:
        raise KsftFailEx(f"Unable to parse xdp_features output: {output}")

    detected = match.group(1) is None
    advertised = match.group(2) is None
    ksft_eq(detected, advertised,
            comment=f"{feature}: detected and advertised support")


def test_xdp_pass(cfg):
    """Check XDP_PASS detection against the advertised capability."""
    run_feature(cfg, "XDP_PASS", "6")


def test_xdp_drop(cfg):
    """Check XDP_DROP detection against the advertised capability."""
    run_feature(cfg, "XDP_DROP", "4")


def test_xdp_aborted(cfg):
    """Check XDP_ABORTED detection against the advertised capability."""
    run_feature(cfg, "XDP_ABORTED", "6")


def test_xdp_tx(cfg):
    """Check XDP_TX detection against the advertised capability."""
    run_feature(cfg, "XDP_TX", "4")


def test_xdp_redirect(cfg):
    """Check XDP_REDIRECT detection against the advertised capability."""
    run_feature(cfg, "XDP_REDIRECT", "6")


def test_xdp_ndo_xmit(cfg):
    """Check XDP_NDO_XMIT detection against the advertised capability."""
    run_feature(cfg, "XDP_NDO_XMIT", "4")


def main():
    """Deploy the helper and run the six feature checks."""
    with NetDrvEpEnv(__file__, nsim_test=False) as cfg:
        cfg.xdp_features = (Path(__file__).parent / "xdp_features").resolve()
        cfg.remote_xdp_features = cfg.remote.deploy(
            cfg.xdp_features.as_posix()
        )

        ksft_run([
            test_xdp_pass,
            test_xdp_drop,
            test_xdp_aborted,
            test_xdp_tx,
            test_xdp_redirect,
            test_xdp_ndo_xmit,
        ], args=(cfg,))
    ksft_exit()


if __name__ == "__main__":
    main()
