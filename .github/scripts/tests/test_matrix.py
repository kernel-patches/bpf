#!/usr/bin/env python3

import unittest
from typing import Any, Dict, List
from unittest import mock

from .. import matrix
from ..matrix import Arch


def runner(name: str, labels: List[str], status: str = "online",
           busy: bool = False) -> Dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "busy": busy,
        "labels": [{"name": label} for label in labels],
    }


BASE = ["self-hosted", "docker-noble-main"]


def mixed_pools(perf_online: int = 2, perf_status: str = "online"):
    """Two s390x pools: 'slow' generic ones and 'perf'-labeled ones."""
    slow = [
        runner(f"bpf-ci-runner-s390x-{i:02}-worker-00", BASE + ["s390x"])
        for i in range(4)
    ]
    perf = [
        runner(f"ebpf{i}-worker-00", BASE + ["s390x", "s390x-perf"],
               status=perf_status)
        for i in range(perf_online)
    ]
    return slow + perf


class TestPreferredRunnerLabel(unittest.TestCase):
    def setUp(self):
        matrix.all_runners_cached = None

    def tearDown(self):
        matrix.all_runners_cached = None

    def test_prefers_labeled_pool_when_online(self):
        with mock.patch.object(matrix, "query_runners_from_github",
                               return_value=mixed_pools(perf_online=2)):
            self.assertEqual(matrix.preferred_runner_label(Arch.S390X),
                             "s390x-perf")

    def test_falls_back_when_too_few_preferred_runners(self):
        with mock.patch.object(matrix, "query_runners_from_github",
                               return_value=mixed_pools(perf_online=1)):
            self.assertIsNone(matrix.preferred_runner_label(Arch.S390X))

    def test_falls_back_when_preferred_pool_offline(self):
        with mock.patch.object(matrix, "query_runners_from_github",
                               return_value=mixed_pools(
                                   perf_online=3, perf_status="offline")):
            self.assertIsNone(matrix.preferred_runner_label(Arch.S390X))

    def test_falls_back_when_label_absent_from_fleet(self):
        """The current fleet: no runner carries the preferred label."""
        slow_only = [r for r in mixed_pools() if "s390x-perf" not in
                     [l["name"] for l in r["labels"]]]
        with mock.patch.object(matrix, "query_runners_from_github",
                               return_value=slow_only):
            self.assertIsNone(matrix.preferred_runner_label(Arch.S390X))

    def test_arch_without_preference_unaffected(self):
        with mock.patch.object(matrix, "query_runners_from_github",
                               return_value=mixed_pools()):
            self.assertIsNone(matrix.preferred_runner_label(Arch.X86_64))

    def test_no_runner_data_is_a_noop(self):
        """Fork PRs get no runner-reading token; the query returns []."""
        with mock.patch.object(matrix, "query_runners_from_github",
                               return_value=[]):
            self.assertIsNone(matrix.preferred_runner_label(Arch.S390X))


class TestRunsOn(unittest.TestCase):
    def setUp(self):
        matrix.all_runners_cached = None

    def tearDown(self):
        matrix.all_runners_cached = None

    def build_config(self, arch: Arch):
        return matrix.BuildConfig(arch=arch, kernel_compiler=matrix.Compiler.GCC)

    def test_s390x_routed_to_preferred_pool(self):
        with mock.patch.object(matrix, "query_runners_from_github",
                               return_value=mixed_pools(perf_online=2)), \
             mock.patch.object(matrix, "is_managed_repo", return_value=True):
            self.assertEqual(self.build_config(Arch.S390X).runs_on,
                             BASE + ["s390x-perf"])

    def test_s390x_generic_label_without_preferred_pool(self):
        with mock.patch.object(matrix, "query_runners_from_github",
                               return_value=[]), \
             mock.patch.object(matrix, "is_managed_repo", return_value=True):
            self.assertEqual(self.build_config(Arch.S390X).runs_on,
                             BASE + ["s390x"])


if __name__ == "__main__":
    unittest.main()
