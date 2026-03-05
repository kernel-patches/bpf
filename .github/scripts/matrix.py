#!/usr/bin/env python3

import dataclasses
import json
import os

from enum import Enum
from typing import Any, Dict, Final, List, Optional, Set, Union

import requests
import requests.utils

MANAGED_OWNER: Final[str] = "kernel-patches"
MANAGED_REPOS: Final[Set[str]] = {
    f"{MANAGED_OWNER}/bpf",
    f"{MANAGED_OWNER}/vmtest",
}

DEFAULT_SELF_HOSTED_RUNNER_TAGS: Final[List[str]] = ["self-hosted", "docker-noble-main"]
DEFAULT_GITHUB_HOSTED_RUNNER: Final[str] = "ubuntu-24.04"
DEFAULT_GCC_VERSION: Final[int] = 15
DEFAULT_LLVM_VERSION: Final[int] = 21

RUNNERS_BUSY_THRESHOLD: Final[float] = 0.8


class Arch(str, Enum):
    """
    CPU architecture supported by CI.
    """

    AARCH64 = "aarch64"
    S390X = "s390x"
    X86_64 = "x86_64"


class Compiler(str, Enum):
    GCC = "gcc"
    LLVM = "llvm"


def query_runners_from_github() -> List[Dict[str, Any]]:
    if "GITHUB_TOKEN" not in os.environ:
        return []
    token = os.environ["GITHUB_TOKEN"]
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    owner = os.environ["GITHUB_REPOSITORY_OWNER"]
    url: Optional[str] = f"https://api.github.com/orgs/{owner}/actions/runners"
    # GitHub returns 30 runners per page, fetch all
    all_runners = []
    try:
        while url is not None:
            response = requests.get(url, headers=headers)
            if response.status_code != 200:
                print(f"Failed to query runners: {response.status_code}")
                print(f"response: {response.text}")
                return []
            data = response.json()
            all_runners.extend(data.get("runners", []))
            # Check for next page URL in Link header
            url = None
            if "Link" in response.headers:
                links = requests.utils.parse_header_links(response.headers["Link"])
                for link in links:
                    if link["rel"] == "next":
                        url = link["url"]
                        break
        return all_runners
    except Exception as e:
        print(f"Warning: Failed to query runner status due to exception: {e}")
        return []


all_runners_cached: Optional[List[Dict[str, Any]]] = None


def all_runners() -> List[Dict[str, Any]]:
    global all_runners_cached
    if all_runners_cached is None:
        print("Querying runners from GitHub...")
        all_runners_cached = query_runners_from_github()
        print(f"Github returned {len(all_runners_cached)} runners")
        counts = count_by_status(all_runners_cached)
        print(
            f"Busy: {counts['busy']}, Idle: {counts['idle']}, Offline: {counts['offline']}"
        )
    return all_runners_cached


def runner_labels(runner: Dict[str, Any]) -> List[str]:
    return [label["name"] for label in runner["labels"]]


def is_self_hosted_runner(runner: Dict[str, Any]) -> bool:
    labels = runner_labels(runner)
    for label in DEFAULT_SELF_HOSTED_RUNNER_TAGS:
        if label not in labels:
            return False
    return True


def self_hosted_runners() -> List[Dict[str, Any]]:
    runners = all_runners()
    return [r for r in runners if is_self_hosted_runner(r)]


def runners_by_arch(arch: Arch) -> List[Dict[str, Any]]:
    runners = self_hosted_runners()
    return [r for r in runners if arch.value in runner_labels(r)]


def count_by_status(runners: List[Dict[str, Any]]) -> Dict[str, int]:
    result = {"busy": 0, "idle": 0, "offline": 0}
    for runner in runners:
        if runner["status"] == "online":
            if runner["busy"]:
                result["busy"] += 1
            else:
                result["idle"] += 1
        else:
            result["offline"] += 1
    return result


@dataclasses.dataclass
class BuildConfig:
    arch: Arch
    kernel_compiler: Compiler = Compiler.GCC
    gcc_version: int = DEFAULT_GCC_VERSION
    llvm_version: int = DEFAULT_LLVM_VERSION
    kernel: str = "LATEST"
    run_veristat: bool = False
    parallel_tests: bool = False
    build_release: bool = False

    @property
    def runs_on(self) -> List[str]:
        if is_managed_repo():
            return DEFAULT_SELF_HOSTED_RUNNER_TAGS + [self.arch.value]
        else:
            return [DEFAULT_GITHUB_HOSTED_RUNNER]

    @property
    def build_runs_on(self) -> List[str]:
        if not is_managed_repo():
            return [DEFAULT_GITHUB_HOSTED_RUNNER]

        # @Temporary: disable codebuild runners for cross-compilation jobs
        match self.arch:
            case Arch.S390X:
                return DEFAULT_SELF_HOSTED_RUNNER_TAGS + [Arch.X86_64.value]
            case Arch.AARCH64:
                return DEFAULT_SELF_HOSTED_RUNNER_TAGS + [Arch.X86_64.value]

        # For managed repos, check the busyness of relevant self-hosted runners
        # If they are too busy, use codebuild
        runner_arch = self.arch
        runners = runners_by_arch(runner_arch)
        counts = count_by_status(runners)
        online = counts["idle"] + counts["busy"]
        busy = counts["busy"]
        # if online <= 0, then something is wrong, don't use codebuild
        if online > 0 and busy / online > RUNNERS_BUSY_THRESHOLD:
            return ["codebuild"]
        else:
            return DEFAULT_SELF_HOSTED_RUNNER_TAGS + [runner_arch.value]

    @property
    def tests(self) -> Dict[str, Any]:
        tests_list = [
            "test_progs",
            "test_progs_parallel",
            "test_progs_no_alu32",
            "test_progs_no_alu32_parallel",
            "test_verifier",
        ]

        if self.arch.value != "s390x":
            tests_list.append("test_maps")

        if self.llvm_version >= 18:
            tests_list.append("test_progs_cpuv4")

        if self.arch in [Arch.X86_64, Arch.AARCH64]:
            tests_list.append("sched_ext")

        # Don't run GCC BPF runner, because too many tests are failing
        # See: https://lore.kernel.org/bpf/87bjw6qpje.fsf@oracle.com/
        # if self.arch == Arch.X86_64:
        #    tests_list.append("test_progs-bpf_gcc")

        if not self.parallel_tests:
            tests_list = [test for test in tests_list if not test.endswith("parallel")]

        return {"include": [generate_test_config(test) for test in tests_list]}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "arch": self.arch.value,
            "kernel_compiler": self.kernel_compiler.value,
            "gcc_version": DEFAULT_GCC_VERSION,
            "llvm_version": DEFAULT_LLVM_VERSION,
            "kernel": self.kernel,
            "run_veristat": self.run_veristat,
            "parallel_tests": self.parallel_tests,
            "build_release": self.build_release,
            "runs_on": self.runs_on,
            "tests": self.tests,
            "build_runs_on": self.build_runs_on,
        }


def is_managed_repo() -> bool:
    return (
        os.environ["GITHUB_REPOSITORY_OWNER"] == MANAGED_OWNER
        and os.environ["GITHUB_REPOSITORY"] in MANAGED_REPOS
    )


def set_output(name, value):
    """Write an output variable to the GitHub output file."""
    with open(os.getenv("GITHUB_OUTPUT"), "a", encoding="utf-8") as file:
        file.write(f"{name}={value}\n")


def generate_test_config(test: str) -> Dict[str, Union[str, int]]:
    """Create the configuration for the provided test."""
    is_parallel = test.endswith("_parallel")
    config = {
        "test": test,
        "continue_on_error": is_parallel,
        # While in experimental mode, parallel jobs may get stuck
        # anywhere, including in user space where the kernel won't detect
        # a problem and panic. We add a second layer of (smaller) timeouts
        # here such that if we get stuck in a parallel run, we hit this
        # timeout and fail without affecting the overall job success (as
        # would be the case if we hit the job-wide timeout). For
        # non-experimental jobs, 360 is the default which will be
        # superseded by the overall workflow timeout (but we need to
        # specify something).
        "timeout_minutes": 30 if is_parallel else 360,
    }
    return config


if __name__ == "__main__":
    matrix = [
        BuildConfig(
            arch=Arch.X86_64,
            run_veristat=True,
            parallel_tests=True,
        ),
        BuildConfig(
            arch=Arch.X86_64,
            kernel_compiler=Compiler.LLVM,
            build_release=True,
        ),
        BuildConfig(
            arch=Arch.AARCH64,
        ),
        BuildConfig(
            arch=Arch.S390X,
        ),
    ]

    # Outside of managed repositories only run on x86_64
    if not is_managed_repo():
        matrix = [config for config in matrix if config.arch == Arch.X86_64]

    json_matrix = json.dumps({"include": [config.to_dict() for config in matrix]})
    print(json.dumps(json.loads(json_matrix), indent=4))
    set_output("build_matrix", json_matrix)
