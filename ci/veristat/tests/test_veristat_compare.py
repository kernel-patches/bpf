#!/usr/bin/env python3

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from typing import Iterable, List

from ..veristat_compare import parse_table, VeristatFields
from .. import veristat_compare as report


def gen_csv_table(records: Iterable[str]) -> List[str]:
    return [
        ",".join(VeristatFields.headers()),
        *records,
    ]


class TestVeristatCompare(unittest.TestCase):
    def test_parse_table_ignore_new_prog(self):
        table = gen_csv_table(
            [
                "prog_file.bpf.o,prog_name,N/A,success,N/A,N/A,1,N/A",
            ]
        )
        veristat_info = parse_table(table)
        self.assertEqual(veristat_info.table, [])
        self.assertFalse(veristat_info.changes)
        self.assertFalse(veristat_info.new_failures)

    def test_parse_table_ignore_removed_prog(self):
        table = gen_csv_table(
            [
                "prog_file.bpf.o,prog_name,success,N/A,N/A,1,N/A,N/A",
            ]
        )
        veristat_info = parse_table(table)
        self.assertEqual(veristat_info.table, [])
        self.assertFalse(veristat_info.changes)
        self.assertFalse(veristat_info.new_failures)

    def test_parse_table_new_failure(self):
        table = gen_csv_table(
            [
                "prog_file.bpf.o,prog_name,success,failure,MISMATCH,1,1,+0 (+0.00%)",
            ]
        )
        veristat_info = parse_table(table)
        self.assertEqual(
            veristat_info.table,
            [["prog_file.bpf.o", "prog_name", "success -> failure (!!)", "+0.00 %"]],
        )
        self.assertTrue(veristat_info.changes)
        self.assertTrue(veristat_info.new_failures)

    def test_parse_table_new_changes(self):
        table = gen_csv_table(
            [
                "prog_file.bpf.o,prog_name,failure,success,MISMATCH,0,0,+0 (+0.00%)",
                "prog_file.bpf.o,prog_name_increase,failure,failure,MATCH,1,2,+1 (+100.00%)",
                "prog_file.bpf.o,prog_name_decrease,success,success,MATCH,1,1,-1 (-100.00%)",
            ]
        )
        veristat_info = parse_table(table)
        self.assertEqual(
            veristat_info.table,
            [
                ["prog_file.bpf.o", "prog_name", "failure -> success", "+0.00 %"],
                ["prog_file.bpf.o", "prog_name_increase", "failure", "+100.00 %"],
                ["prog_file.bpf.o", "prog_name_decrease", "success", "-100.00 %"],
            ],
        )
        self.assertTrue(veristat_info.changes)
        self.assertFalse(veristat_info.new_failures)


class TestVeristatReport(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.results = self.root / "results"
        self.baseline = self.root / "baseline"
        self.results.mkdir()
        self.baseline.mkdir()
        self.config = self.root / "config.json"
        self.config.write_text(json.dumps([{"name": "a"}, {"name": "b"}]))
        self.statuses = {name: {"state": "measured"} for name in ("a", "b")}
        header = "file_name,prog_name,verdict,total_states\n"
        for name, verdict, states in (("a", "failure", 0), ("b", "success", 2)):
            (self.results / f"{name}.csv").write_text(
                header + f"same.bpf.o,prog,{verdict},{states}\n"
            )
            (self.baseline / f"{name}.csv").write_text(
                header + "same.bpf.o,prog,success,1\n"
            )

    def invoke(self):
        (self.results / "status.json").write_text(json.dumps(self.statuses))

        def compare(command, stdout, **kwargs):
            record = (
                "same.bpf.o,prog,success,failure,MISMATCH,1,0,-1 (-100.00%)"
                if Path(command[-1]).stem == "a"
                else "same.bpf.o,prog,success,success,MATCH,1,2,+1 (+100.00%)"
            )
            stdout.write("\n".join(gen_csv_table([record])) + "\n")
            return subprocess.CompletedProcess(command, 0)

        args = [
            "report",
            "--config",
            str(self.config),
            "--results",
            str(self.results),
            "--baseline",
            str(self.baseline),
            "--veristat",
            "/usr/bin/true",
        ]
        with patch.object(sys, "argv", args), patch.dict(
            os.environ,
            GITHUB_STEP_SUMMARY=str(self.root / "summary.md"),
            GITHUB_OUTPUT=str(self.root / "outputs"),
        ), patch.object(
            report.subprocess, "run", side_effect=compare
        ), contextlib.redirect_stdout(
            io.StringIO()
        ) as output:
            result = report.main()
        return result, output.getvalue()

    def test_regression_and_later_source_both_reported(self):
        result, text = self.invoke()
        self.assertEqual(result, 1)
        self.assertEqual(text.count("# Veristat"), 1)
        self.assertRegex(text, r"\|a\s*\|same.bpf.o\s*\|prog\s*\|success -> failure")
        self.assertRegex(text, r"\|b\s*\|same.bpf.o\s*\|prog\s*\|success")
        self.assertLess(text.index("success -> failure"), text.index("+100.00 %"))
        self.assertIn("measured=a b", (self.root / "outputs").read_text())

    def test_missing_and_failed_sources_remain_visible(self):
        self.config.write_text(
            json.dumps([{"name": name} for name in ("a", "b", "failed", "missing")])
        )
        self.statuses["failed"] = {"state": "error", "error": "fixture failure"}
        (self.baseline / "b.csv").unlink()
        result, text = self.invoke()
        self.assertEqual(result, 1)
        for outcome in ("No baseline", "Measurement error", "Not run"):
            self.assertIn(outcome, text)

    def test_empty_measured_results_do_not_pass(self):
        (self.results / "a.csv").write_text("")
        for file in self.baseline.iterdir():
            file.unlink()
        self.assertEqual(self.invoke()[0], 1)


if __name__ == "__main__":
    unittest.main()
