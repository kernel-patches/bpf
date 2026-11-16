import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from .. import run_veristat as runner


class RunnerTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.results = self.root / "results"
        (self.root / "object.bpf.o").write_bytes(b"BPF object")
        self.corpus = {
            "name": "test",
            "objects": {"object.bpf.o": hashlib.sha256(b"BPF object").hexdigest()},
        }
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(json.dumps({"version": 1, "corpora": [self.corpus]}))
        self.csv = (
            "file_name,prog_name,verdict,total_states\nobject.bpf.o,prog,failure,0\n"
        )

    def tool_output(self, command, stdout, stderr, **kwargs):
        stdout.write(self.csv)
        return subprocess.CompletedProcess(command, 0)

    def invoke(self):
        args = [
            "run_veristat",
            "--veristat=/usr/bin/true",
            f"--manifest={self.manifest}",
            f"--output={self.results}",
        ]
        with patch.object(sys, "argv", args), patch.object(
            runner.subprocess, "run", side_effect=self.tool_output
        ):
            return runner.main()

    def test_empty_measurement_does_not_pass(self):
        self.csv = self.csv.splitlines()[0] + "\n"
        self.assertNotEqual(self.invoke(), 0)

    def test_changed_object_does_not_pass(self):
        (self.root / "object.bpf.o").write_bytes(b"changed")
        self.assertNotEqual(self.invoke(), 0)

    def test_completed_receipt_uses_object_basename(self):
        (self.root / "moved").mkdir()
        (self.root / "object.bpf.o").rename(self.root / "moved/object.bpf.o")
        self.corpus["objects"] = {
            "moved/object.bpf.o": self.corpus["objects"]["object.bpf.o"]
        }
        self.manifest.write_text(json.dumps({"version": 1, "corpora": [self.corpus]}))
        self.assertEqual(self.invoke(), 0)
        status = json.loads((self.results / "test/status.json").read_text())
        self.assertEqual(status["state"], "measured")
        self.assertEqual(
            status["corpus_sha256"],
            "730cbbe4991552fc640e8bb57604945c63e4afa3f5a57cbcce831e1ca10d6a40",
        )

    def test_guest_records_incomplete_measurement_as_failure(self):
        script = Path(runner.__file__).parent / "run-veristat.sh"
        result = subprocess.run(
            [str(script)],
            env=dict(
                os.environ,
                VERISTAT_BINARY="/usr/bin/true",
                VERISTAT_MANIFEST=str(self.manifest),
                VERISTAT_RESULTS=str(self.results),
                STATUS_FILE=str(self.root / "exitstatus"),
            ),
            capture_output=True,
            text=True,
        )
        self.assertIn(
            "veristat:1",
            (self.root / "exitstatus").read_text().splitlines(),
            result.stderr,
        )
