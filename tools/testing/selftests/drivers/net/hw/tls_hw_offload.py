#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

"""Test kTLS hardware offload using a C helper binary."""

from collections import defaultdict

from lib.py import ksft_run, ksft_exit, ksft_pr, KsftSkipEx
from lib.py import ksft_ge, ksft_eq
from lib.py import ksft_variants, KsftNamedVariant
from lib.py import NetDrvEpEnv
from lib.py import cmd, bkg, wait_port_listen, rand_port
from lib.py import CmdExitFailure

# Burst variants push hundreds of MB and perform many rekeys, so they
# need far longer than the default cmd() timeout.
BURST_TIMEOUT_S = 180
REKEY_TIMEOUT_S = 90

# Reading /proc/net/tls_stat is trivial locally, but on the remote it runs
# over ssh, where connection setup can occasionally spike past the short
# default cmd() timeout. Give these tiny reads plenty of headroom so a slow
# ssh round-trip doesn't fail an otherwise-good variant.
STATS_TIMEOUT_S = 30

# Per-packet HW crypto counters exposed via `ethtool -S` on the DUT NIC,
# keyed by the `ethtool -i` driver name. TlsTxDevice/TlsRxDevice in
# /proc/net/tls_stat only prove tls_dev_add() accepted the offload; these
# increment once per packet the NIC actually encrypted/decrypted (mlx5 counts
# gso_segs, not records), so they prove the HW crypto path was exercised.
# Names are driver-specific, so the
# check only runs on drivers listed here and is skipped (not failed) on
# others, keeping the test portable across NICs.
HW_CRYPTO_COUNTERS = {
    'mlx5_core': {'Tx': 'tx_tls_encrypted_packets',
                  'Rx': 'rx_tls_decrypted_packets'},
}


def check_tls_support(cfg):
    """Skip the suite unless both hosts have kTLS and the DUT HW offload."""
    # The tls module is autoloaded lazily on the first TCP_ULP="tls"
    # setsockopt, so /proc/net/tls_stat (created from the module's pernet
    # init) may not exist yet on a freshly booted host. Load the module
    # explicitly before probing for it.
    try:
        cmd("modprobe tls")
        cmd("modprobe tls", host=cfg.remote)
        cmd("test -f /proc/net/tls_stat")
        cmd("test -f /proc/net/tls_stat", host=cfg.remote)
    except CmdExitFailure as e:
        raise KsftSkipEx(f"kTLS not supported: {e}") from e

    try:
        features = cmd(f"ethtool -k {cfg.ifname}").stdout
        if 'tls-hw-tx-offload: on' not in features:
            raise KsftSkipEx("Device does not support TLS HW TX offload")
        if 'tls-hw-rx-offload: on' not in features:
            raise KsftSkipEx("Device does not support TLS HW RX offload")
    except CmdExitFailure as e:
        raise KsftSkipEx(f"Cannot determine TLS HW offload support: {e}") from e


def read_tls_stats(host=None):
    """Snapshot the per-netns TLS MIB from /proc/net/tls_stat as a dict."""
    # /proc/net/tls_stat exposes the per-netns TLS MIB (TLS_INC_STATS on
    # sock_net(sk)). The test runs on a real NIC in the host namespace, so
    # these counters are shared with anything else doing kTLS there. The
    # strict before/after delta checks (exact rekey-outcome sums, zero error
    # counters) assume no other kTLS activity in this namespace during a
    # variant's window; concurrent kTLS users would perturb the deltas and
    # cause spurious failures. Don't run other kTLS workloads alongside this
    # test.
    stats = defaultdict(int)
    output = cmd("cat /proc/net/tls_stat", host=host, timeout=STATS_TIMEOUT_S)
    for line in output.stdout.strip().split('\n'):
        parts = line.split()
        if len(parts) == 2:
            stats[parts[0]] = int(parts[1])
    return stats


def nic_driver(cfg):
    """DUT NIC driver name from `ethtool -i`, or None if undetermined."""
    try:
        output = cmd(f"ethtool -i {cfg.ifname}").stdout
    except CmdExitFailure:
        return None
    for line in output.splitlines():
        if line.startswith('driver:'):
            return line.split(':', 1)[1].strip()
    return None


def read_nic_stats(cfg):
    """Snapshot the DUT NIC's `ethtool -S` counters as a dict."""
    # Driver per-record TLS counters from `ethtool -S` on the DUT NIC. Same
    # before/after-delta caveat as read_tls_stats(): these are device-wide,
    # so concurrent kTLS traffic on this NIC would perturb the deltas.
    stats = defaultdict(int)
    output = cmd(f"ethtool -S {cfg.ifname}").stdout
    for line in output.strip().split('\n'):
        key, sep, val = line.partition(':')
        if sep and val.strip().isdigit():
            stats[key.strip()] = int(val.strip())
    return stats


def stat_diff(before, after, key):
    """Return the delta of counter `key` between two stat snapshots."""
    return after[key] - before[key]


def check_hw_crypto(cfg, before, after, with_tx, with_rx):
    """DUT-side ethtool -S check: the NIC actually crypto'd records in HW.

    Complements the TlsTxDevice/TlsRxDevice MIBs, which only confirm the
    offload was installed, not that any record was processed in hardware.
    Driver-specific; skipped (without failing) on drivers not in
    HW_CRYPTO_COUNTERS so the test stays portable.
    """
    counters = HW_CRYPTO_COUNTERS.get(cfg.nic_driver)
    if not counters:
        ksft_pr(f"NOTE: DUT driver '{cfg.nic_driver}' has no known per-record "
                f"HW crypto counters, skipping ethtool -S check")
        return

    for direction, active in (('Tx', with_tx), ('Rx', with_rx)):
        if not active:
            continue
        key = counters[direction]
        if key not in after:
            ksft_pr(f"NOTE: DUT {direction}: counter '{key}' not exposed by "
                    f"{cfg.nic_driver}, skipping")
            continue
        got = stat_diff(before, after, key)
        ksft_ge(got, 1,
                comment=f"DUT {direction}: NIC reported no HW crypto "
                        f"({key}={got})")


def check_path(before, after, direction, role, require_hw):
    """On the DUT, require HW offload; on the remote, HW or SW is fine."""
    dev = stat_diff(before, after, f'Tls{direction}Device')
    sw = stat_diff(before, after, f'Tls{direction}Sw')
    if require_hw:
        ksft_ge(dev, 1,
                comment=f"{role} {direction}: HW offload not engaged "
                        f"(Device={dev}, Sw={sw})")
    else:
        ksft_ge(dev + sw, 1,
                comment=f"{role} {direction}: no TLS activity "
                        f"(Device={dev}, Sw={sw})")


def verify_tls_counters(stats_before, stats_after, expected_rekeys,
                        tls_role, is_dut, burst=False, allow_fallback=False):
    """Verify TLS counters on one side of the connection.

    tls_role: 'client' or 'server' (TLS role this side played).
    is_dut: True for the local DUT; requires HW offload counters.
    burst: burst mode - only the TLS client rotates its TX key; the TLS
           server only follows with an RX rotation on KeyUpdate receipt.
    allow_fallback: tolerate rekeys completing in SW (TlsRx/TxRekeyFallback).
           Default False: a rekey on an up, offload-capable device must stay
           in HW, so any fallback is a regression. Set True only where SW
           fallback is expected (e.g. a mid-connection link-flap variant, or
           the peer, whose offload state is not under test).
    """
    role = 'DUT' if is_dut else 'Peer'

    def diff(key):
        return stat_diff(stats_before, stats_after, key)

    # In burst mode the TLS client only TXs and the TLS server only RXs.
    # In echo mode both sides drive both directions.
    with_tx = not burst or tls_role == 'client'
    with_rx = not burst or tls_role != 'client'

    if with_tx:
        check_path(stats_before, stats_after, 'Tx', role, require_hw=is_dut)
    if with_rx:
        check_path(stats_before, stats_after, 'Rx', role, require_hw=is_dut)

    if expected_rekeys > 0:
        if with_tx:
            # Each KeyUpdate yields exactly one terminal outcome, so
            #   TlsTxRekeyOk + TlsTxRekeyAborted + TlsTxRekeyFallback == N.
            # At most one rekey can be PENDING at socket close (single
            # TLS_TX_REKEY_PENDING bit), so at most one lands in
            # TlsTxRekeyAborted. TlsTxRekeyFallback is a legitimate, graceful
            # degradation: the device did not (re)install the HW context for
            # that rekey (device gone, dev_add rejected, or a transient
            # crypto/alloc error) so it completed in SW while the kernel
            # returned success. It is recoverable - the next KeyUpdate
            # re-attempts HW offload (tls_device_start_rekey() clears
            # TLS_TX_REKEY_FAILED). It is folded into the outcome sum below; on
            # the DUT it must be 0 (allow_fallback=False), on the peer it is
            # only NOTEd. A genuine rekey bug still surfaces as TlsTxRekeyError.
            ksft_ge(1, diff('TlsTxRekeyAborted'),
                    comment=f"{role} Tx: TlsTxRekeyAborted expected <= 1")
            ksft_eq(diff('TlsTxRekeyOk') + diff('TlsTxRekeyAborted') +
                    diff('TlsTxRekeyFallback'), expected_rekeys,
                    comment=f"{role} Tx: rekey outcomes must sum to "
                            f"{expected_rekeys}")
            fallback = diff('TlsTxRekeyFallback')
            if allow_fallback:
                if fallback:
                    ksft_pr(f"NOTE: {role} Tx: {fallback} rekey(s) completed "
                            f"in SW (TlsTxRekeyFallback); HW not re-installed")
            else:
                ksft_eq(fallback, 0,
                        comment=f"{role} Tx: TlsTxRekeyFallback expected 0 "
                                f"(rekey must stay in HW offload)")
            ksft_eq(diff('TlsTxRekeyError'), 0,
                    comment=f"{role} Tx: TlsTxRekeyError expected 0")
            ksft_eq(diff('TlsCurrTxRekey'), 0,
                    comment=f"{role} Tx: TlsCurrTxRekey expected 0")
        if with_rx:
            # As on TX, each received KeyUpdate yields one terminal outcome:
            #   TlsRxRekeyOk + TlsRxRekeyAborted + TlsRxRekeyFallback == N.
            # At most one rekey can be deferred (single dev_add_pending) at
            # socket close, landing in TlsRxRekeyAborted. TlsRxRekeyFallback
            # is a recoverable, graceful degradation (dev_add failed or the
            # device was gone, so RX temporarily dropped to SW; the next
            # KeyUpdate re-adds the HW context and clears TLS_RX_DEV_DEGRADED).
            # It is folded into the outcome sum below; on the DUT it must be 0
            # (allow_fallback=False), on the peer it is only NOTEd. A genuine
            # rekey bug still surfaces as TlsRxRekeyError.
            ksft_ge(1, diff('TlsRxRekeyAborted'),
                    comment=f"{role} Rx: TlsRxRekeyAborted expected <= 1")
            ksft_eq(diff('TlsRxRekeyOk') + diff('TlsRxRekeyAborted') +
                    diff('TlsRxRekeyFallback'), expected_rekeys,
                    comment=f"{role} Rx: rekey outcomes must sum to "
                            f"{expected_rekeys}")
            ksft_eq(diff('TlsRxRekeyReceived'), expected_rekeys,
                    comment=f"{role} Rx: TlsRxRekeyReceived expected "
                            f"{expected_rekeys}")
            fallback = diff('TlsRxRekeyFallback')
            if allow_fallback:
                if fallback:
                    ksft_pr(f"NOTE: {role} Rx: {fallback} rekey(s) completed "
                            f"in SW (TlsRxRekeyFallback); HW not re-installed")
            else:
                ksft_eq(fallback, 0,
                        comment=f"{role} Rx: TlsRxRekeyFallback expected 0 "
                                f"(rekey must stay in HW offload)")
            ksft_eq(diff('TlsRxRekeyError'), 0,
                    comment=f"{role} Rx: TlsRxRekeyError expected 0")
            ksft_eq(diff('TlsCurrRxRekey'), 0,
                    comment=f"{role} Rx: TlsCurrRxRekey expected 0")

    ksft_eq(diff('TlsDecryptError'), 0,
            comment=f"{role}: TlsDecryptError expected 0")


def run_tls_test(cfg, cipher="128", tls_version="1.3", rekey=0,
                 buffer_size=None, random_max=None, burst=False, zc=False,
                 dut_role="client", num_iterations=None, ipver="4"):
    """Run the TLS offload test.

    dut_role: 'client' (default) - DUT runs the TLS client, remote the server.
              'server' - swap: DUT listens, remote connects. Used for burst_rx
              so the DUT's RX path is the one under rekey pressure.

    ipver: '4' or '6' - IP version to run over. The C helper is forced to the
           matching family with -4/-6 and connects to the peer's v4/v6 address.
           Variants requesting '6' skip cleanly when the environment lacks IPv6
           connectivity (require_ipver()).

    The DUT (local) is the kernel under test; the remote is just a traffic
    source/sink and may run any kernel without HW offload. Both sides run
    kTLS because TLS is pairwise, but verify_tls_counters() requires HW
    offload only on the DUT (is_dut=True); the peer may use SW kTLS.

    Rekey/burst variants additionally require the peer to support TLS 1.3
    KeyUpdate (as the RX or TX side of the rotation). SW KeyUpdate and its
    MIB counters landed together in v6.14; an older peer cannot follow the
    rotation, so those variants are skipped rather than failed when the peer
    lacks the rekey counters (see the probe below).
    """
    cfg.require_ipver(ipver)

    port = rand_port()
    send_size = random_max or buffer_size

    if dut_role == "client":
        server_bin, server_host = cfg.bin_remote, cfg.remote
        client_bin, client_host = cfg.bin_local, None
        client_target = cfg.remote_addr_v[ipver]
    else:
        server_bin, server_host = cfg.bin_local, None
        client_bin, client_host = cfg.bin_remote, cfg.remote
        client_target = cfg.addr_v[ipver]

    server_parts = [f"{server_bin} server -p {port} -c {cipher}",
                    f"-v {tls_version}", f"-{ipver}"]
    if burst:
        server_parts.append("-B")
    if zc:
        server_parts.append("-Z")
    if send_size:
        server_parts.append(f"-b {send_size}")
    server_cmd = " ".join(server_parts)

    client_parts = [f"{client_bin} client -s {client_target}",
                    f"-p {port} -c {cipher} -v {tls_version} -{ipver}"]
    if rekey:
        client_parts.append(f"-k {rekey}")
    if burst:
        client_parts.append("-B")
    if num_iterations:
        client_parts.append(f"-n {num_iterations}")
    if random_max:
        client_parts.append(f"-r {random_max}")
    elif buffer_size:
        client_parts.append(f"-b {buffer_size}")
    client_cmd = " ".join(client_parts)

    if burst:
        cmd_timeout = BURST_TIMEOUT_S
    elif rekey:
        cmd_timeout = REKEY_TIMEOUT_S
    else:
        cmd_timeout = 20

    stats_before_local = read_tls_stats()
    stats_before_remote = read_tls_stats(host=cfg.remote)
    nic_before = read_nic_stats(cfg)

    # /proc/net/tls_stat lists every MIB the running kernel knows (0 or not),
    # so a missing name means the peer predates that counter. The base rekey
    # counters (TlsRxRekeyReceived, Tls{Rx,Tx}RekeyOk, Tls{Rx,Tx}RekeyError)
    # shipped with SW KeyUpdate in v6.14; a peer without them cannot follow a
    # KeyUpdate, so the rekey/burst variants can't run against it. Skip cleanly
    # here rather than letting the peer-side rekey-sum / RxRekeyReceived checks
    # report a confusing "expected N, got 0" later. TlsRxRekeyReceived is a
    # reliable probe: the peer must bump it to have processed the rotation at all.
    #
    # Only a base v6.14 counter is probed. The newer HW-path MIBs (Aborted,
    # Fallback, CurrRekey) are structurally 0 on a SW-only peer and defaultdict
    # returns 0 for absent names, so the peer-side checks hold either way.
    if rekey and 'TlsRxRekeyReceived' not in stats_before_remote:
        raise KsftSkipEx("Peer kernel lacks TLS 1.3 KeyUpdate support "
                         "(no rekey MIB counters); required for rekey tests")

    with bkg(server_cmd, host=server_host, exit_wait=True):
        wait_port_listen(port, host=server_host)
        # Start the client in the background so we keep a handle to it. A
        # foreground cmd() raises TimeoutExpired from inside its constructor
        # if the client hangs, and since the child is not killed on timeout
        # it would be left running with no handle to reap it. A leaked
        # client keeps bumping the per-netns TLS counters (TlsTxRekeyAborted,
        # TlsDecryptError, ...) and would corrupt the before/after
        # measurement window of a later variant. The finally clause reaps it
        # within this variant's window instead.
        client = cmd(client_cmd, host=client_host, background=True)
        try:
            client.process(terminate=False, fail=True, timeout=cmd_timeout)
        finally:
            if client.proc.poll() is None:
                client.process(terminate=True, fail=False, timeout=5)

    stats_after_local = read_tls_stats()
    stats_after_remote = read_tls_stats(host=cfg.remote)
    nic_after = read_nic_stats(cfg)

    peer_tls_role = 'server' if dut_role == 'client' else 'client'

    # Which directions the DUT drives (mirrors verify_tls_counters()): in
    # burst mode the TLS client only TXs and the server only RXs; echo mode
    # drives both.
    dut_with_tx = not burst or dut_role == 'client'
    dut_with_rx = not burst or dut_role != 'client'

    verify_tls_counters(stats_before_local, stats_after_local,
                        rekey, dut_role, is_dut=True, burst=burst)
    check_hw_crypto(cfg, nic_before, nic_after, dut_with_tx, dut_with_rx)
    verify_tls_counters(stats_before_remote, stats_after_remote,
                        rekey, peer_tls_role, is_dut=False, burst=burst,
                        allow_fallback=True)


# The cipher/version matrix runs over IPv4; the socket setup is the only
# IP-version-specific code path, so a single representative variant over
# IPv6 is enough to cover it (it skips cleanly without v6 connectivity).
# The rekey and burst suites below likewise stay on IPv4 to bound runtime.
@ksft_variants([
    KsftNamedVariant("tls13_aes128", "128", "1.3", "4"),
    KsftNamedVariant("tls13_aes256", "256", "1.3", "4"),
    KsftNamedVariant("tls12_aes128", "128", "1.2", "4"),
    KsftNamedVariant("tls12_aes256", "256", "1.2", "4"),
    KsftNamedVariant("tls13_aes128_ip6", "128", "1.3", "6"),
])
def test_tls_offload(cfg, cipher, tls_version, ipver):
    """Cipher/version matrix over the HW offload data path, no rekey."""
    run_tls_test(cfg, cipher=cipher, tls_version=tls_version, ipver=ipver)


@ksft_variants([
    KsftNamedVariant("single", 1),
    KsftNamedVariant("multiple", 99),
    KsftNamedVariant("small_buf", 30, 512),
    KsftNamedVariant("large_buf", 10, 2097152),
    KsftNamedVariant("random_buf", 20, None, 8192),
])
def test_tls_offload_rekey(cfg, rekey, buffer_size=None, random_max=None):
    """Echo-mode TLS 1.3 KeyUpdate rekeys across a range of buffer sizes."""
    run_tls_test(cfg, cipher="128", tls_version="1.3", rekey=rekey,
                 buffer_size=buffer_size, random_max=random_max)


# Columns:                                          dut_role  zc     interval rekeys buffer_size
@ksft_variants([
    KsftNamedVariant("burst_tx_rekey_every_1",        "client", False, 1,       50,    65536),
    KsftNamedVariant("burst_tx_rekey_every_1000",     "client", False, 1000,    3,     65536),
    KsftNamedVariant("burst_rx_rekey_every_10",       "server", False, 10,      20,    65536),
    KsftNamedVariant("burst_rx_rekey_every_10000",    "server", False, 10000,   1,     32768),
    KsftNamedVariant("burst_rx_zc_rekey_every_100",   "server", True,  100,     10,    65536),
    KsftNamedVariant("burst_rx_zc_rekey_every_20000", "server", True,  20000,   1,     16384),
])
def test_tls_offload_burst(cfg, dut_role, zc, interval, rekeys, buffer_size):
    """High-volume one-directional traffic with frequent rekeys."""
    run_tls_test(cfg, cipher="128", tls_version="1.3", rekey=rekeys,
                 buffer_size=buffer_size, burst=True, zc=zc, dut_role=dut_role,
                 num_iterations=interval * (rekeys + 1))


def main() -> None:
    """Set up the DUT/peer environment and run the offload test suites."""
    with NetDrvEpEnv(__file__, nsim_test=False) as cfg:
        cfg.bin_local = cfg.test_dir / "tls_hw_offload"
        if not cfg.bin_local.exists():
            raise KsftSkipEx(f"tls_hw_offload binary not found at {cfg.bin_local}")
        cfg.bin_remote = cfg.remote.deploy(cfg.bin_local)
        cfg.require_ipver("4")
        check_tls_support(cfg)
        cfg.nic_driver = nic_driver(cfg)

        ksft_run([test_tls_offload, test_tls_offload_rekey,
                  test_tls_offload_burst], args=(cfg, ))
    ksft_exit()


if __name__ == "__main__":
    main()
