#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

"""
Tests for XDP metadata kfuncs (e.g. bpf_xdp_metadata_rx_hash).

These tests load device-bound XDP programs from xdp_metadata.bpf.o
that call metadata kfuncs, send traffic, and verify the extracted
metadata via BPF maps.

The skb core extension test loads xdp_skb_ext.bpf.o: an XDP program
stores RX metadata and a tc program checks it on the skb.
"""
import socket

from lib.py import ksft_run, ksft_eq, ksft_exit, ksft_ge, ksft_ne, ksft_pr
from lib.py import KsftNamedVariant, ksft_variants
from lib.py import CmdExitFailure, KsftSkipEx, NetDrvEpEnv
from lib.py import NetdevFamily
from lib.py import bkg, cmd, rand_port, wait_port_listen
from lib.py import ip, bpftool, defer, ethtool, tc, set_ethtool_feat
from lib.py import bpf_map_set, bpf_map_dump, bpf_prog_map_ids


def _load_xdp_metadata_prog(cfg, prog_name, bpf_file="xdp_metadata.bpf.o"):
    """Load a device-bound XDP metadata program and return prog/map info.

    Returns:
        dict with 'id', 'name', and 'maps' (name -> map_id).
    """
    abs_path = cfg.net_lib_dir / bpf_file
    pin_dir = "/sys/fs/bpf/xdp_metadata_test"

    cmd(f"rm -rf {pin_dir}", shell=True, fail=False)
    cmd(f"mkdir -p {pin_dir}", shell=True)

    try:
        bpftool(f"prog loadall {abs_path} {pin_dir} type xdp "
                f"xdpmeta_dev {cfg.ifname}")
    except CmdExitFailure as e:
        cmd(f"rm -rf {pin_dir}", shell=True, fail=False)
        raise KsftSkipEx(
            f"Failed to load device-bound XDP program '{prog_name}'"
        ) from e
    defer(cmd, f"rm -rf {pin_dir}", shell=True, fail=False)

    pin_path = f"{pin_dir}/{prog_name}"
    ip(f"link set dev {cfg.ifname} xdpdrv pinned {pin_path}")
    defer(ip, f"link set dev {cfg.ifname} xdpdrv off")

    xdp_info = ip(f"-d link show dev {cfg.ifname}", json=True)[0]
    prog_id = xdp_info["xdp"]["prog"]["id"]

    return {"id": prog_id,
            "name": xdp_info["xdp"]["prog"]["name"],
            "maps": bpf_prog_map_ids(prog_id)}


def _send_probe(cfg, port, proto="tcp"):
    """Send a single payload from the remote end using socat.

    Args:
        cfg: Configuration object containing network settings.
        port: Port number for the exchange.
        proto: Protocol to use, either "tcp" or "udp".
    """
    cfg.require_cmd("socat", remote=True)

    if proto == "tcp":
        rx_cmd = f"socat -{cfg.addr_ipver} -T 2 TCP-LISTEN:{port},reuseport STDOUT"
        tx_cmd = f"echo -n rss_hash_test | socat -t 2 -u STDIN TCP:{cfg.baddr}:{port}"
    else:
        rx_cmd = f"socat -{cfg.addr_ipver} -T 2 -u UDP-RECV:{port},reuseport STDOUT"
        tx_cmd = f"echo -n rss_hash_test | socat -t 2 -u STDIN UDP:{cfg.baddr}:{port}"

    with bkg(rx_cmd, exit_wait=True):
        wait_port_listen(port, proto=proto)
        cmd(tx_cmd, host=cfg.remote, shell=True)


# BPF map keys matching the enums in xdp_metadata.bpf.c
_SETUP_KEY_PORT = 1

_RSS_KEY_HASH = 0
_RSS_KEY_TYPE = 1
_RSS_KEY_PKT_CNT = 2
_RSS_KEY_ERR_CNT = 3

XDP_RSS_L4 = 0x8  # BIT(3) from enum xdp_rss_hash_type


@ksft_variants([
    KsftNamedVariant("tcp", "tcp"),
    KsftNamedVariant("udp", "udp"),
])
def test_xdp_rss_hash(cfg, proto):
    """Test RSS hash metadata extraction via bpf_xdp_metadata_rx_hash().

    This test will only run on devices that support xdp-rx-metadata-features.

    Loads the xdp_rss_hash program from xdp_metadata, sends a packet using
    the specified protocol, and verifies that the program extracted a non-zero
    hash with an L4 hash type.
    """
    dev_info = cfg.netnl.dev_get({"ifindex": cfg.ifindex})
    rx_meta = dev_info.get("xdp-rx-metadata-features", [])
    if "hash" not in rx_meta:
        raise KsftSkipEx("device does not support XDP rx hash metadata")

    prog_info = _load_xdp_metadata_prog(cfg, "xdp_rss_hash")

    port = rand_port()
    bpf_map_set("map_xdp_setup", _SETUP_KEY_PORT, port)

    rss_map_id = prog_info["maps"]["map_rss"]

    _send_probe(cfg, port, proto=proto)

    rss = bpf_map_dump(rss_map_id)

    pkt_cnt = rss.get(_RSS_KEY_PKT_CNT, 0)
    err_cnt = rss.get(_RSS_KEY_ERR_CNT, 0)
    hash_val = rss.get(_RSS_KEY_HASH, 0)
    hash_type = rss.get(_RSS_KEY_TYPE, 0)

    ksft_ge(pkt_cnt, 1, comment="should have received at least one packet")
    ksft_eq(err_cnt, 0, comment=f"RSS hash error count: {err_cnt}")

    ksft_ne(hash_val, 0,
            f"RSS hash should be non-zero for {proto.upper()} traffic")
    ksft_pr(f"  RSS hash: {hash_val:#010x}")

    ksft_pr(f"  RSS hash type: {hash_type:#06x}")
    ksft_ne(hash_type & XDP_RSS_L4, 0,
            f"RSS hash type should include L4 for {proto.upper()} traffic")


# BPF map keys matching the enums in xdp_skb_ext.bpf.c
_CFG_PORT = 0
_CFG_HASH = 1
_CFG_VLAN_PROTO = 2
_CFG_VLAN_TCI = 3
_CFG_IP_SUMMED = 4
_CFG_CSUM_LEVEL = 5

_RES_PKT_CNT = 0
_RES_STORE_ERR = 1
_RES_HASH = 2
_RES_L4_HASH = 3
_RES_VLAN_PROTO = 4
_RES_VLAN_TCI = 5
_RES_IP_SUMMED = 6
_RES_CSUM_LEVEL = 7

ETH_P_8021AD = 0x88a8
VLAN_PRIO_SHIFT = 13

# Magic numbers the NIC does not report
TEST_RX_HASH = 0x12345678
TEST_VLAN_PCP = 5
TEST_VLAN_VID = 0xabc
TEST_VLAN_TCI = TEST_VLAN_PCP << VLAN_PRIO_SHIFT | TEST_VLAN_VID

XDP_CHECKSUM_NONE = 1 << 0
XDP_CHECKSUM_UNNECESSARY = 1 << 1
CHECKSUM_NONE = 0
CHECKSUM_UNNECESSARY = 1


def _load_skb_ext_progs(cfg):
    """Attach the store program to XDP and the check program to tc ingress.

    Returns:
        A dict mapping map name to map ID.
    """
    abs_path = cfg.test_dir / "xdp_skb_ext.bpf.o"
    pin_dir = "/sys/fs/bpf/xdp_skb_ext_test"

    cmd(f"rm -rf {pin_dir}", shell=True, fail=False)
    cmd(f"mkdir -p {pin_dir}", shell=True)
    defer(cmd, f"rm -rf {pin_dir}", shell=True, fail=False)

    bpftool(f"prog loadall {abs_path} {pin_dir}")
    ip(f"link set dev {cfg.ifname} xdpdrv pinned {pin_dir}/xdp_store")
    defer(ip, f"link set dev {cfg.ifname} xdpdrv off")

    qdiscs = tc(f"qdisc show dev {cfg.ifname}", json=True)
    if not any(q["kind"] == "clsact" for q in qdiscs):
        tc(f"qdisc add dev {cfg.ifname} clsact")
        defer(tc, f"qdisc del dev {cfg.ifname} clsact")

    tc(f"filter add dev {cfg.ifname} ingress bpf "
       f"object-pinned {pin_dir}/tc_check direct-action")
    prog_id = bpftool(f"prog show pinned {pin_dir}/tc_check", json=True)["id"]
    for f in tc(f"filter show dev {cfg.ifname} ingress", json=True):
        if f.get("options", {}).get("prog", {}).get("id") == prog_id:
            defer(tc, f"filter del dev {cfg.ifname} ingress pref {f['pref']}")

    return bpf_prog_map_ids(prog_id)


@ksft_variants([
    KsftNamedVariant("csum_none", XDP_CHECKSUM_NONE, 0, CHECKSUM_NONE),
    KsftNamedVariant("csum_unnecessary", XDP_CHECKSUM_UNNECESSARY, 1,
                     CHECKSUM_UNNECESSARY),
])
def test_xdp_skb_ext(cfg, xdp_csum, csum_level, ip_summed):
    """Test that the skb gets the RX metadata stored on XDP_PASS.

    The XDP program stores a hash, a VLAN tag and a checksum status that
    differ from what the NIC reports. The tc program reads them from the
    skb.
    """
    dev_info = cfg.netnl.dev_get({"ifindex": cfg.ifindex})
    if "skb-ext-pass" not in dev_info.get("xdp-features", []):
        raise KsftSkipEx("device does not support skb-ext-pass")

    maps = _load_skb_ext_progs(cfg)

    # GRO can change ip_summed before tc ingress
    feat = ethtool(f"-k {cfg.ifname}", json=True)[0]
    set_ethtool_feat(cfg.ifname, feat, {"generic-receive-offload": False})

    cfg_map = "map_store_cfg"
    bpf_map_set(cfg_map, _CFG_HASH, TEST_RX_HASH)
    bpf_map_set(cfg_map, _CFG_VLAN_PROTO, ETH_P_8021AD)
    bpf_map_set(cfg_map, _CFG_VLAN_TCI, TEST_VLAN_TCI)
    bpf_map_set(cfg_map, _CFG_IP_SUMMED, xdp_csum)
    bpf_map_set(cfg_map, _CFG_CSUM_LEVEL, csum_level)
    # The port goes last: it enables the store for the test packets
    port = rand_port(socket.SOCK_DGRAM)
    bpf_map_set(cfg_map, _CFG_PORT, port)

    _send_probe(cfg, port, proto="udp")

    res = bpf_map_dump(maps["map_store_res"])
    ksft_ge(res.get(_RES_PKT_CNT, 0), 1, "tc saw the test packet")
    ksft_eq(res.get(_RES_STORE_ERR, 0), 0, "store kfunc errors")

    ksft_eq(res.get(_RES_HASH, 0), TEST_RX_HASH, "skb->hash")
    ksft_eq(res.get(_RES_L4_HASH, 0), 1, "skb->l4_hash")
    ksft_eq(res.get(_RES_VLAN_PROTO, 0), ETH_P_8021AD, "skb->vlan_proto")
    ksft_eq(res.get(_RES_VLAN_TCI, 0), TEST_VLAN_TCI, "skb->vlan_tci")
    ksft_eq(res.get(_RES_IP_SUMMED, 0), ip_summed, "skb->ip_summed")
    ksft_eq(res.get(_RES_CSUM_LEVEL, 0), csum_level, "skb->csum_level")


def main():
    """Run XDP metadata kfunc tests against a real device."""
    with NetDrvEpEnv(__file__) as cfg:
        cfg.netnl = NetdevFamily()
        ksft_run(
            [
                test_xdp_rss_hash,
                test_xdp_skb_ext,
            ],
            args=(cfg,))
    ksft_exit()


if __name__ == "__main__":
    main()
