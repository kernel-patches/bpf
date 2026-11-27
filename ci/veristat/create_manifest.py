#!/usr/bin/env python3
"""Describe selected local objects for a veristat measurement."""

import argparse
import json
import os
from pathlib import Path

from run_veristat import file_sha256


def make_corpus(selection, parent):
    corpus = {
        "name": selection["name"],
        "objects": {
            os.path.relpath(path, parent): file_sha256(path)
            for path in sorted(
                Path(selection["directory"]).absolute().glob(selection["pattern"])
            )
            if path.is_file()
        },
    }
    if selection.get("filter"):
        corpus["filter"] = os.path.relpath(Path(selection["filter"]).absolute(), parent)
    return corpus


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    parent = args.output.absolute().parent
    corpora = [
        make_corpus(selection, parent)
        for selection in json.loads(args.config.read_text())
    ]
    args.output.write_text(
        json.dumps({"version": 1, "corpora": corpora}, indent=2) + "\n"
    )


if __name__ == "__main__":
    main()
