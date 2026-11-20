#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Summarize Alpha ProfileMe samples.

Aggregates the ProfileMe status that the Alpha cpu PMU attaches to each
sample as PERF_SAMPLE_RAW data, by symbol or, with --pc, by instruction.

Record with raw data, e.g.:
  perf record -R -e cpu/instructions,profileme/ -- ./workload
A precise event such as instructions:p samples only retired instructions,
so its killed% and invalid% columns read 0.
  alpha-profileme.py [-i perf.data] [--pc] [--top N]

Columns:
  samples   ProfileMe samples attributed to the row
  killed%   profiled instruction killed before it was mapped (PM_KILLED_BM)
  invalid%  instruction did not trap and did not retire valid (VAL clear)
  mispr%    conditional branch mispredicted (TRP and MIS)
  taken%    TAK set; only meaningful for rows that are conditional branches
  stall%    instruction stalled between fetch and map (PM_STALLED)
  pctr1     mean PCTR1 count during the window; what it counts depends on
            the event: inum retire delay for cycles:p, window cycles for
            instructions:p, Bcache misses for bcache-misses:p and Mbox
            replay traps for cpu/mbox-replay/p
  traps     trap counts by type, only for samples with TRP set

TRP, and MIS and the trap type with it, are stale for a killed instruction,
so mispr%, invalid% and traps ignore them there.

Samples from events that set PCTR1 to count different things are printed
in separate tables, as their means cannot be compared.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import struct
import sys
from typing import Optional
import perf

TRAP_TYPES = {
    0: "replay", 2: "dtb2-3l", 3: "dtb2-4l", 4: "fen", 5: "unalign",
    6: "dtb1", 7: "dfault", 8: "opcdec", 10: "mchk", 12: "arith",
    14: "mt_fpcr", 15: "reset",
}
REDIRECTS = {0x481: "iacv", 0x581: "itbmiss", 0x681: "intr"}
PCTR1_NAMES = ("cycles", "retire delay", "bcache misses", "mbox replays")
SAMPLE = struct.Struct("<IQQQ")


class Row:
    """ProfileMe status totals for one symbol or instruction."""
    def __init__(self) -> None:
        self.samples = 0
        self.killed = 0
        self.invalid = 0
        self.mispredict = 0
        self.taken = 0
        self.stalled = 0
        self.pctr1 = 0
        self.traps: dict[str, int] = defaultdict(int)


def pct(n: int, d: int) -> float:
    """Return n as a percentage of d."""
    return 100.0 * n / d if d else 0.0


class ProfileMe:
    """Aggregates ProfileMe raw sample data."""
    def __init__(self, by_pc: bool, top: int) -> None:
        self.by_pc = by_pc
        self.top = top
        # Keyed by PCTR_CTL[SL1], which sets what PCTR1 counts.
        self.tables: dict[int, dict[str, Row]] = defaultdict(lambda: defaultdict(Row))
        self.skipped = 0
        self.session: Optional[perf.session] = None

    def process_event(self, sample: perf.sample_event) -> None:
        """Add one sample's ProfileMe status to its row."""
        raw = sample.raw_buf
        # Raw data from another PMU or a tracepoint is not ProfileMe status.
        if (sample.evsel.type not in (perf.TYPE_HARDWARE, perf.TYPE_RAW) or
                not raw or len(raw) < SAMPLE.size):
            self.skipped += 1
            return
        version, pmpc, i_stat, ctl = SAMPLE.unpack_from(raw)
        if version < 1:
            self.skipped += 1
            return

        symbol = sample.symbol or "[unknown]"
        if self.by_pc:
            if pmpc & 1:
                key = f"PAL+{pmpc & 0x7fff:#x}"
            else:
                key = f"{pmpc & ~3:#018x} {symbol}"
        else:
            key = f"{sample.dso or '[unknown]'} {symbol}"

        r = self.tables[(ctl >> 2) & 3][key]
        r.samples += 1
        killed = (ctl >> 26) & 1
        trp = (i_stat >> 39) & 1 and not killed
        if killed:
            r.killed += 1
        if not trp and not (ctl >> 1) & 1:
            r.invalid += 1
        if ctl & 1:
            r.taken += 1
        if (ctl >> 27) & 1:
            r.stalled += 1
        r.pctr1 += (ctl >> 6) & 0xfffff

        redirect = REDIRECTS.get(pmpc & 0x7fff) if pmpc & 1 else None
        if redirect:
            r.traps[redirect] += 1
        elif trp:
            if (i_stat >> 40) & 1:
                r.mispredict += 1
            else:
                tt = (i_stat >> 34) & 0xf
                r.traps[TRAP_TYPES.get(tt, "other")] += 1

    def print_totals(self) -> None:
        """Print the busiest rows of each table."""
        total = sum(r.samples for rows in self.tables.values() for r in rows.values())
        print(f"{total} ProfileMe samples, {self.skipped} without ProfileMe data")
        for sl1, rows in sorted(self.tables.items()):
            print(f"\npctr1 counts {PCTR1_NAMES[sl1]}:")
            self.print_table(rows)

    def print_table(self, rows: dict[str, Row]) -> None:
        """Print the busiest rows of one table."""
        print(f"{'samples':>8} {'killed%':>7} {'invalid%':>8} {'mispr%':>6} "
              f"{'taken%':>7} {'stall%':>6} {'pctr1':>7}  {'location':<40} traps")
        ordered = sorted(rows.items(), key=lambda kv: kv[1].samples, reverse=True)
        for key, r in ordered[:self.top]:
            traps = " ".join(f"{k}={v}" for k, v in
                             sorted(r.traps.items(), key=lambda kv: -kv[1]))
            print(f"{r.samples:8d} {pct(r.killed, r.samples):7.1f} "
                  f"{pct(r.invalid, r.samples):8.1f} "
                  f"{pct(r.mispredict, r.samples):6.1f} "
                  f"{pct(r.taken, r.samples):7.1f} "
                  f"{pct(r.stalled, r.samples):6.1f} "
                  f"{r.pctr1 / r.samples:7.1f}  {key:<40} {traps}")

    def run(self, input_file: str) -> None:
        """Run the session."""
        self.session = perf.session(perf.data(input_file), sample=self.process_event)
        try:
            self.session.process_events()
        finally:
            # Break the reference cycle between perf.session and self.process_event
            # because perf.session lacks cyclic GC support (tp_traverse).
            self.session = None
        self.print_totals()


def main() -> None:
    """Main function."""
    parser = argparse.ArgumentParser(description="Summarize Alpha ProfileMe samples")
    parser.add_argument("-i", "--input", default="perf.data", help="Input file")
    parser.add_argument("--pc", action="store_true", help="aggregate by instruction")
    parser.add_argument("--top", type=int, default=30, help="rows to print")
    args = parser.parse_args()

    analyzer = ProfileMe(args.pc, args.top)
    try:
        analyzer.run(args.input)
    except IOError as e:
        print(e, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
