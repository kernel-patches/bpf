#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

"""Measure TCP stream throughput with kperf."""

from lib.py import KperfRunner, KsftNamedVariant, NetDrvEpEnv, ksft_exit
from lib.py import ksft_metric, ksft_run, ksft_variants


@ksft_variants([
    KsftNamedVariant("copy", []),
    KsftNamedVariant("zerocopy", ["--msg-zerocopy", "--zerocopy-rx"]),
])
def tcp(cfg, mode_args) -> None:
    """Measure the throughput of one TCP connection."""
    stream_args = [
        "--time", "15",
        "--num-connections", "1",
        "--read-size", str(64 << 20),
        "--write-size", str(64 << 20),
        "--pin-off", "4",
        "--validate", "no",
        *mode_args,
    ]

    with KperfRunner(cfg) as runner:
        result = runner.run(stream_args)

    ksft_metric("throughput", result.target_throughput, goal="higher")


def main() -> None:
    """Run the stream performance test."""
    with NetDrvEpEnv(__file__, nsim_test=False) as cfg:
        ksft_run([tcp], args=(cfg,))
    ksft_exit()


if __name__ == "__main__":
    main()
