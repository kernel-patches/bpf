#!/usr/bin/env python3
"""Measure prepared BPF corpora against the running kernel."""

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

CSV_FIELDS = ["file_name", "prog_name", "verdict", "total_states"]


def log(message):
    print(f"run-veristat: {message}", file=sys.stderr, flush=True)


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def corpus_sha256(objects):
    names = {Path(path).name: digest for path, digest in objects.items()}
    if len(names) != len(objects):
        raise ValueError("object basenames must be unique within a corpus")
    listing = "".join(f"{names[name]}  {name}\n" for name in sorted(names))
    return hashlib.sha256(listing.encode()).hexdigest()


def write_status(directory, status):
    temporary = directory / "status.tmp"
    temporary.write_text(json.dumps(status, indent=2) + "\n")
    temporary.replace(directory / "status.json")


def validate_results(path):
    with path.open(newline="") as stream:
        rows = csv.reader(stream)
        programs = 0
        rejected = []
        try:
            if next(rows, None) != CSV_FIELDS:
                raise ValueError("unexpected veristat CSV header")
            for row in rows:
                if len(row) != len(CSV_FIELDS):
                    raise ValueError("incomplete veristat CSV record")
                filename, program, verdict, states = row
                if not filename or not program or verdict not in ("success", "failure"):
                    raise ValueError("invalid veristat program result")
                if states != "N/A":
                    try:
                        int(states)
                    except ValueError:
                        raise ValueError("invalid total_states value") from None
                if verdict == "failure":
                    rejected.append((filename, program))
                programs += 1
            if not programs:
                raise ValueError("veristat produced no program results")
        except (ValueError, csv.Error) as error:
            raise ValueError(f"{path}:{max(rows.line_num, 1)}: {error}") from None
    return programs, rejected


def record_rejected(veristat, paths, rejected, output, name):
    files = {file for file, _ in rejected}
    objects = [path for path in paths if Path(path).name in files]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg") as config, (
        output / "failures.log"
    ).open("a") as log_file:
        config.write("".join(f"{file}/{program}\n" for file, program in rejected))
        config.flush()
        log_file.write(f"\n# {name}\n")
        log_file.flush()
        result = subprocess.run(
            [str(veristat), "-v", f"-f@{config.name}"] + objects,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
    return result.returncode


def measure(veristat, manifest_path, output):
    manifest_path = Path(manifest_path).absolute()
    veristat = Path(veristat).absolute()
    output = Path(output).absolute()
    log(
        f"kernel={os.uname().release} binary={veristat} "
        f"manifest={manifest_path} output={output}"
    )
    manifest = json.loads(manifest_path.read_text())
    if manifest["version"] != 1 or not manifest["corpora"]:
        raise ValueError("expected a version 1 manifest with at least one corpus")
    output.mkdir(parents=True)
    (output / "stderr.log").touch()
    statuses = {}
    for corpus in manifest["corpora"]:
        name = corpus["name"]
        if name in statuses:
            raise ValueError(f"duplicate corpus name: {name}")
        csv_path = output / f"{name}.csv"
        status = {"state": "running"}
        statuses[name] = status
        write_status(output, statuses)
        rejected = []
        try:
            objects = corpus["objects"]
            config = (
                manifest_path.parent / corpus["filter"]
                if corpus.get("filter")
                else None
            )
            log(f"{name}: checking {len(objects)} objects; filter={config or 'none'}")
            if not objects:
                raise ValueError("corpus contains no objects")
            status["corpus_sha256"] = corpus_sha256(objects)
            paths = []
            for relative, expected in sorted(objects.items()):
                path = manifest_path.parent / relative
                actual = file_sha256(path)
                if actual != expected:
                    raise ValueError(
                        f"object checksum mismatch: {path}; expected={expected} actual={actual}"
                    )
                paths.append(str(path))
            command = [
                str(veristat),
                "-o",
                "csv",
                "-q",
                "-e",
                "file,prog,verdict,states",
            ]
            if config:
                command.append(f"-f@{config}")
            with csv_path.open("w") as stdout, tempfile.TemporaryFile() as stderr:
                log(
                    f"{name}: running veristat; corpus_sha256={status['corpus_sha256']}"
                )
                result = subprocess.run(command + paths, stdout=stdout, stderr=stderr)
                if stderr.tell():
                    stderr.seek(0)
                    with (output / "stderr.log").open("ab") as log_file:
                        log_file.write(f"\n# {name}\n".encode())
                        shutil.copyfileobj(stderr, log_file)
            status["returncode"] = result.returncode
            if result.returncode:
                raise ValueError(
                    f"veristat exited with status {result.returncode}; "
                    f"stderr={output / 'stderr.log'}"
                )
            programs, rejected = validate_results(csv_path)
            status["state"] = "measured"
            message = f"{name}: measured {programs} programs"
        except (OSError, ValueError, csv.Error) as error:
            status.update(state="error", error=str(error))
            message = f"{name}: error: {error}"
        write_status(output, statuses)
        log(message)
        # Diagnostics only: keep verbose logs from the measured kernel and objects.
        if rejected:
            try:
                returncode = record_rejected(veristat, paths, rejected, output, name)
                log(
                    f"{name}: recorded verifier logs of {len(rejected)} rejected "
                    f"programs in {output / 'failures.log'}; exit status {returncode}"
                )
            except OSError as error:
                log(f"{name}: could not record verifier logs: {error}")
    return statuses


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--veristat", required=True)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        statuses = measure(args.veristat, args.manifest, args.output)
    except (OSError, ValueError) as error:
        log(f"error: {error}")
        return 1
    return int(any(status["state"] != "measured" for status in statuses.values()))


if __name__ == "__main__":
    sys.exit(main())
