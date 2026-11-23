#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

"""Measure TCP request-response performance with kperf."""

from lib.py import KperfRunner, NetDrvEpEnv, ksft_exit, ksft_metric, ksft_run


# One connection, a kilobyte each way, which fits in a 1500 byte MTU, and
# latency percentiles
RR_ARGS = [
    "--time", "10",
    "--warmup", "100",
    "--num-connections", "1",
    "--req-size", "1024",
    "--resp-size", "1024",
    "--time-stats", "2",
    "--validate", "no",
]


def _report(result) -> None:
    ksft_metric("rate", result.rate, goal="higher")
    ksft_metric("latency_p25", result.p25, goal="lower")
    ksft_metric("latency_p50", result.p50, goal="lower")
    ksft_metric("latency_p90", result.p90, goal="lower")
    ksft_metric("latency_p99", result.p99, goal="lower")
    ksft_metric("latency_p999", result.p999, goal="lower")
    ksft_metric("latency_p9999", result.p9999, goal="lower")
    ksft_metric("latency_max", result.lat_max, goal="lower")


def closed_loop(cfg) -> None:
    """Measure back-to-back transactions."""
    with KperfRunner(cfg) as runner:
        _report(runner.run(RR_ARGS))


def main() -> None:
    """Run the request-response performance tests."""
    with NetDrvEpEnv(__file__, nsim_test=False) as cfg:
        ksft_run([closed_loop], args=(cfg,))
    ksft_exit()


if __name__ == "__main__":
    main()
