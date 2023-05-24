#!/usr/bin/env python3

# This script reads a CSV file produced by the following invocation:
#
#   veristat --emit file,prog,verdict,states \
#            --output-format csv \
#            --compare ...
#
# And produces a markdown summary for the file.
# The summary is printed to standard output and appended to a file
# pointed to by GITHUB_STEP_SUMMARY variable.
#
# Script exits with return code 1 if there are new failures in the
# veristat results.
#
# For testing purposes invoke as follows:
#
#  GITHUB_STEP_SUMMARY=/dev/null python3 veristat-compare.py test.csv
#
# File format (columns):
#  0. file_name
#  1. prog_name
#  2. verdict_base
#  3. verdict_comp
#  4. verdict_diff
#  5. total_states_base
#  6. total_states_comp
#  7. total_states_diff
#
# Records sample:
#  file-a,a,success,failure,MISMATCH,12,12,+0 (+0.00%)
#  file-b,b,success,success,MATCH,67,67,+0 (+0.00%)
#
# For better readability suffixes '_OLD' and '_NEW'
# are used instead of '_base' and '_comp' for variable
# names etc.

import io
import os
import sys
import csv
import logging
import argparse
from functools import reduce
from dataclasses import dataclass

TRESHOLD_PCT = 0

HEADERS = ['file_name', 'prog_name', 'verdict_base', 'verdict_comp',
           'verdict_diff', 'total_states_base', 'total_states_comp',
           'total_states_diff']

FILE        = 0
PROG        = 1
VERDICT_OLD = 2
VERDICT_NEW = 3
STATES_OLD  = 5
STATES_NEW  = 6

# Given a table row, compute relative increase in the number of
# processed states.
def compute_diff(v):
    old = int(v[STATES_OLD]) if v[STATES_OLD] != 'N/A' else 0
    new = int(v[STATES_NEW]) if v[STATES_NEW] != 'N/A' else 0
    if old == 0:
        return 1
    return (new - old) / old

@dataclass
class VeristatInfo:
    table: list
    changes: bool
    new_failures: bool

# Read CSV table expecting the above described format.
# Return VeristatInfo instance.
def parse_table(csv_filename):
    new_failures = False
    changes = False
    table = []

    with open(csv_filename, newline='') as file:
        reader = csv.reader(file)
        headers = next(reader)
        if headers != HEADERS:
            raise Exception(f'Unexpected table header for {filename}: {headers}')

        for v in reader:
            add = False
            verdict = v[VERDICT_NEW]
            diff = compute_diff(v)

            if v[VERDICT_OLD] != v[VERDICT_NEW]:
                changes = True
                add = True
                verdict = f'{v[VERDICT_OLD]} -> {v[VERDICT_NEW]}'
                if v[VERDICT_NEW] == 'failure':
                    new_failures = True
                    verdict += ' (!!)'

            if abs(diff * 100) > TRESHOLD_PCT:
                changes = True
                add = True

            if not add:
                continue

            diff_txt = '{:+.1f} %'.format(diff * 100)
            table.append([v[FILE], v[PROG], verdict, diff_txt])

    return VeristatInfo(table=table,
                        changes=changes,
                        new_failures=new_failures)

def format_table(headers, rows, html_mode):
    def decorate(val, width):
        s = str(val)
        if html_mode:
            s = s.replace(' -> ', ' &rarr; ');
            s = s.replace(' (!!)', ' :bangbang: ');
        return s.ljust(width)

    column_widths = list(reduce(lambda acc, row: map(max, map(len, row), acc),
                                rows,
                                map(len, headers)))

    with io.StringIO() as out:
        def print_row(row):
            out.write('| ')
            out.write(' | '.join(map(decorate, row, column_widths)))
            out.write(' |\n')

        print_row(headers)

        out.write('|')
        out.write('|'.join(map(lambda w: '-' * (w + 2), column_widths)))
        out.write('|\n')

        for row in rows:
            print_row(row)

        return out.getvalue()

def format_section_name(info):
    if info.new_failures:
        return 'There are new veristat failures'
    if info.changes:
        return 'There are changes in verification performance'
    return 'No changes in verification performance'

SUMMARY_HEADERS = ['File', 'Program', 'Verdict', 'States Diff (%)']

def format_html_summary(info):
    section_name = format_section_name(info)
    if not info.table:
        return f'# {section_name}\n'

    table = format_table(SUMMARY_HEADERS, info.table, True)
    return f'''
# {section_name}

<details>
<summary>Click to expand</summary>

{table}
</details>
'''.lstrip()

def format_text_summary(info):
    section_name = format_section_name(info)
    table = format_table(SUMMARY_HEADERS, info.table, False)
    if not info.table:
        return f'# {section_name}\n'

    return f'''
# {section_name}

{table}
'''.lstrip()

def main(compare_csv_filename, summary_filename):
    info = parse_table(compare_csv_filename)
    sys.stdout.write(format_text_summary(info))
    with open(summary_filename, 'a') as f:
        f.write(format_html_summary(info))

    if info.new_failures:
        return 1

    return 0

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="""Print veristat comparison output as markdown step summary"""
    )
    parser.add_argument('filename')
    args = parser.parse_args()
    summary_filename = os.getenv('GITHUB_STEP_SUMMARY')
    if not summary_filename:
        logging.error('GITHUB_STEP_SUMMARY environment variable is not set')
        sys.exit(1)
    sys.exit(main(args.filename, summary_filename))
