#!/usr/bin/env python3

"""Report a batch of veristat results and compare its cached baselines."""

import io
import os
import sys
import re
import csv
import json
import logging
import argparse
import enum
from dataclasses import dataclass
from pathlib import Path
import subprocess
import tempfile
from typing import Dict, Iterable, List, Final, Optional

TRESHOLD_PCT: Final[int] = 0

SUMMARY_HEADERS = ["Source", "File", "Program", "Verdict", "States Diff (%)"]
OVERVIEW_HEADERS = ["Source", "Programs", "Passed", "Failed", "Status"]

# expected format: +0 (+0.00%) / -0 (-0.00%)
TOTAL_STATES_DIFF_REGEX = (
    r"(?P<absolute_diff>[+-]\d+) \((?P<percentage_diff>[+-]\d+\.\d+)\%\)"
)


GITHUB_MARKUP_REPLACEMENTS: Final[Dict[str, str]] = {
    "->": "&rarr;",
    "(!!)": ":bangbang:",
}

NEW_FAILURE_SUFFIX: Final[str] = "(!!)"


class VeristatFields(str, enum.Enum):
    FILE_NAME = "file_name"
    PROG_NAME = "prog_name"
    VERDICT_OLD = "verdict_base"
    VERDICT_NEW = "verdict_comp"
    VERDICT_DIFF = "verdict_diff"
    TOTAL_STATES_OLD = "total_states_base"
    TOTAL_STATES_NEW = "total_states_comp"
    TOTAL_STATES_DIFF = "total_states_diff"

    @classmethod
    def headers(cls) -> List[str]:
        return [
            cls.FILE_NAME,
            cls.PROG_NAME,
            cls.VERDICT_OLD,
            cls.VERDICT_NEW,
            cls.VERDICT_DIFF,
            cls.TOTAL_STATES_OLD,
            cls.TOTAL_STATES_NEW,
            cls.TOTAL_STATES_DIFF,
        ]


@dataclass
class VeristatInfo:
    table: list
    changes: bool
    new_failures: bool


@dataclass
class SourceReport:
    name: str
    outcome: str
    # A comparison error does not invalidate measured CSVs for baseline staging.
    counts: Optional[List[str]] = None
    comparison: Optional[VeristatInfo] = None
    error: bool = False


def get_state_diff(value: str) -> float:
    if value == "N/A":
        return 0.0

    matches = re.match(TOTAL_STATES_DIFF_REGEX, value)
    if not matches:
        raise ValueError(f"Failed to parse total states diff field value '{value}'")

    if percentage_diff := matches.group("percentage_diff"):
        return float(percentage_diff)

    raise ValueError(f"Invalid {VeristatFields.TOTAL_STATES_DIFF} field value: {value}")


def parse_table(csv_file: Iterable[str]) -> VeristatInfo:
    reader = csv.DictReader(csv_file)
    assert reader.fieldnames == VeristatFields.headers()

    new_failures = False
    changes = False
    table = []

    for record in reader:
        add = False

        verdict_old, verdict_new = (
            record[VeristatFields.VERDICT_OLD],
            record[VeristatFields.VERDICT_NEW],
        )

        # Ignore results from completely new and removed programs
        if "N/A" in [verdict_new, verdict_old]:
            continue

        if record[VeristatFields.VERDICT_DIFF] == "MISMATCH":
            changes = True
            add = True
            verdict = f"{verdict_old} -> {verdict_new}"
            if verdict_new == "failure":
                new_failures = True
                verdict += f" {NEW_FAILURE_SUFFIX}"
        else:
            verdict = record[VeristatFields.VERDICT_NEW]

        diff = get_state_diff(record[VeristatFields.TOTAL_STATES_DIFF])
        if abs(diff) > TRESHOLD_PCT:
            changes = True
            add = True

        if not add:
            continue

        table.append(
            [
                record[VeristatFields.FILE_NAME],
                record[VeristatFields.PROG_NAME],
                verdict,
                f"{diff:+.2f} %",
            ]
        )

    return VeristatInfo(table=table, changes=changes, new_failures=new_failures)


def github_markup_decorate(input_str: str) -> str:
    for text, markup in GITHUB_MARKUP_REPLACEMENTS.items():
        input_str = input_str.replace(text, markup)
    return input_str


def format_table(headers: List[str], rows: List[List[str]]) -> str:
    column_width = [
        max(len(row[column_idx]) for row in [headers] + rows)
        for column_idx in range(len(headers))
    ]

    # Row template string in the following format:
    # "{0:8}|{1:10}|{2:15}|{3:7}|{4:10}"
    row_template = "|".join(
        f"{{{idx}:{width}}}" for idx, width in enumerate(column_width)
    )
    row_template_nl = f"|{row_template}|\n"

    with io.StringIO() as out:
        out.write(row_template_nl.format(*headers))

        separator_row = ["-" * width for width in column_width]
        out.write(row_template_nl.format(*separator_row))

        for row in rows:
            row_str = row_template_nl.format(*row)
            out.write(row_str)

        return out.getvalue()


def render_report(overview, changes, compared, markup=False):
    report = "# Veristat\n\n" + format_table(OVERVIEW_HEADERS, overview)
    if changes:
        table = format_table(SUMMARY_HEADERS, changes)
        if markup:
            report += (
                "\n<details>\n<summary>Changed programs</summary>\n\n"
                + github_markup_decorate(table)
                + "\n</details>\n"
            )
        else:
            report += "\n" + table
    elif compared:
        report += "\nNo verification changes among compared programs.\n"
    return report + "\n"


def compare_results(veristat, baseline, results):
    with tempfile.TemporaryFile(mode="w+") as comparison:
        subprocess.run(
            [
                str(veristat.absolute()),
                "--output-format",
                "csv",
                "--emit",
                "file,prog,verdict,states",
                "--compare",
                str(baseline),
                str(results),
            ],
            stdout=comparison,
            check=True,
        )
        comparison.seek(0)
        return parse_table(comparison)


def source_error(name, csv_path, error, counts=None):
    print(
        f"{name}: results/comparison error for {csv_path}: {type(error).__name__}: {error}",
        file=sys.stderr,
    )
    return SourceReport(name, "Error", counts, error=True)


def summarize_source(name, status, results, baseline, veristat):
    if status.get("state") != "measured":
        outcome = {"running": "Interrupted", "error": "Measurement error"}.get(
            status.get("state"), "Not run"
        )
        if status.get("error"):
            print(
                f"{name}: {status['error']}; see {results / 'status.json'}",
                file=sys.stderr,
            )
        return SourceReport(name, outcome, error=True)

    csv_path = results / f"{name}.csv"
    try:
        with csv_path.open(newline="") as file:
            records = list(csv.DictReader(file))
        if not records:
            raise ValueError("no measured program records")
        passed = sum(record["verdict"] == "success" for record in records)
        counts = [str(len(records)), str(passed), str(len(records) - passed)]
    except (OSError, ValueError, KeyError, csv.Error) as error:
        return source_error(name, csv_path, error)

    if baseline is None:
        return SourceReport(name, "Measured", counts)
    baseline_path = baseline / f"{name}.csv"
    try:
        if not baseline_path.is_file():
            return SourceReport(name, "No baseline", counts)
        comparison = compare_results(veristat, baseline_path, csv_path)
    except (
        OSError,
        ValueError,
        KeyError,
        csv.Error,
        AssertionError,
        subprocess.CalledProcessError,
    ) as error:
        return source_error(name, csv_path, error, counts)
    return SourceReport(name, "Compared", counts, comparison)


def changed_rows(reports):
    changes = []
    for report in reports:
        if report.comparison is not None:
            changes.extend([report.name] + row for row in report.comparison.table)

    changes.sort(
        key=lambda row: (
            NEW_FAILURE_SUFFIX not in row[3],
            -abs(float(row[4].removesuffix(" %"))),
            row[:3],
        )
    )
    return changes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--veristat", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args()
    summary_filename = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_filename:
        logging.error("GITHUB_STEP_SUMMARY environment variable is not set")
        return 1

    status_file = args.results / "status.json"
    statuses = json.loads(status_file.read_text()) if status_file.exists() else {}
    reports = [
        summarize_source(
            selection["name"],
            statuses.get(selection["name"], {}),
            args.results,
            args.baseline,
            args.veristat,
        )
        for selection in json.loads(args.config.read_text())
    ]
    overview = [
        [report.name, *(report.counts or ["-", "-", "-"]), report.outcome]
        for report in reports
    ]
    changes = changed_rows(reports)
    compared = sum(report.comparison is not None for report in reports)
    sys.stdout.write(render_report(overview, changes, compared))
    with open(summary_filename, "a", encoding="utf-8") as file:
        file.write("\n\n" + render_report(overview, changes, compared, markup=True))
    if output_filename := os.getenv("GITHUB_OUTPUT"):
        measured = sorted(
            report.name for report in reports if report.counts is not None
        )
        with open(output_filename, "a", encoding="utf-8") as file:
            file.write(f"measured={' '.join(measured)}\n")
    return int(
        any(
            report.error or (report.comparison and report.comparison.new_failures)
            for report in reports
        )
    )


if __name__ == "__main__":
    sys.exit(main())
