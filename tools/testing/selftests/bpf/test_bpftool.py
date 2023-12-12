# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2020 SUSE LLC.

import collections
import functools
import json
import os
import socket
import subprocess
import unittest
import io


# Add the source tree of bpftool and /usr/local/sbin to PATH
cur_dir = os.path.dirname(os.path.realpath(__file__))
bpftool_dir = os.path.abspath(os.path.join(cur_dir, "..", "..", "..", "..",
                                           "tools", "bpf", "bpftool"))
os.environ["PATH"] = bpftool_dir + ":/usr/local/sbin:" + os.environ["PATH"]


class IfaceNotFoundError(Exception):
    pass


class UnprivilegedUserError(Exception):
    pass


class MissingDependencyError(Exception):
    pass


def _bpftool(args, json=True):
    _args = ["bpftool"]
    if json:
        _args.append("-j")
    _args.extend(args)

    return subprocess.check_output(_args)


def bpftool(args):
    return _bpftool(args, json=False).decode("utf-8")


def bpftool_json(args):
    res = _bpftool(args)
    return json.loads(res)


def get_default_iface():
    for iface in socket.if_nameindex():
        if iface[1] != "lo":
            return iface[1]
    raise IfaceNotFoundError("Could not find any network interface to probe")


def default_iface(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        iface = get_default_iface()
        return f(*args, iface, **kwargs)
    return wrapper

DMESG_EMITTING_HELPERS = [
        "bpf_probe_write_user",
        "bpf_trace_printk",
        "bpf_trace_vprintk",
    ]

DUMMY_SK_BUFF_USER_OBJ = cur_dir + "/dummy_sk_buff_user.bpf.o"
DUMMY_NO_CONTEXT_BTF_OBJ = cur_dir + "/dummy_no_context_btf.bpf.o"

class TestBpftool(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.getuid() != 0:
            raise UnprivilegedUserError(
                "This test suite needs root privileges")
        objs = [DUMMY_SK_BUFF_USER_OBJ,
                DUMMY_NO_CONTEXT_BTF_OBJ]
        for obj in objs:
            if os.path.exists(obj):
                continue
            raise MissingDependencyError(
                "File " + obj + " does not exist, make sure progs/*.c are compiled")

    @default_iface
    def test_feature_dev_json(self, iface):
        unexpected_helpers = DMESG_EMITTING_HELPERS
        expected_keys = [
            "syscall_config",
            "program_types",
            "map_types",
            "helpers",
            "misc",
        ]

        res = bpftool_json(["feature", "probe", "dev", iface])
        # Check if the result has all expected keys.
        self.assertCountEqual(res.keys(), expected_keys)
        # Check if unexpected helpers are not included in helpers probes
        # result.
        for helpers in res["helpers"].values():
            for unexpected_helper in unexpected_helpers:
                self.assertNotIn(unexpected_helper, helpers)

    def test_feature_kernel(self):
        test_cases = [
            bpftool_json(["feature", "probe", "kernel"]),
            bpftool_json(["feature", "probe"]),
            bpftool_json(["feature"]),
        ]
        unexpected_helpers = DMESG_EMITTING_HELPERS
        expected_keys = [
            "syscall_config",
            "system_config",
            "program_types",
            "map_types",
            "helpers",
            "misc",
        ]

        for tc in test_cases:
            # Check if the result has all expected keys.
            self.assertCountEqual(tc.keys(), expected_keys)
            # Check if unexpected helpers are not included in helpers probes
            # result.
            for helpers in tc["helpers"].values():
                for unexpected_helper in unexpected_helpers:
                    self.assertNotIn(unexpected_helper, helpers)

    def test_feature_kernel_full(self):
        test_cases = [
            bpftool_json(["feature", "probe", "kernel", "full"]),
            bpftool_json(["feature", "probe", "full"]),
        ]
        expected_helpers = DMESG_EMITTING_HELPERS

        for tc in test_cases:
            # Check if expected helpers are included at least once in any
            # helpers list for any program type. Unfortunately we cannot assume
            # that they will be included in all program types or a specific
            # subset of programs. It depends on the kernel version and
            # configuration.
            found_helpers = False

            for helpers in tc["helpers"].values():
                if all(expected_helper in helpers
                       for expected_helper in expected_helpers):
                    found_helpers = True
                    break

            self.assertTrue(found_helpers)

    def test_feature_kernel_full_vs_not_full(self):
        full_res = bpftool_json(["feature", "probe", "full"])
        not_full_res = bpftool_json(["feature", "probe"])
        not_full_set = set()
        full_set = set()

        for helpers in full_res["helpers"].values():
            for helper in helpers:
                full_set.add(helper)

        for helpers in not_full_res["helpers"].values():
            for helper in helpers:
                not_full_set.add(helper)

        self.assertCountEqual(full_set - not_full_set,
                              set(DMESG_EMITTING_HELPERS))
        self.assertCountEqual(not_full_set - full_set, set())

    def test_feature_macros(self):
        expected_patterns = [
            r"/\*\*\* System call availability \*\*\*/",
            r"#define HAVE_BPF_SYSCALL",
            r"/\*\*\* eBPF program types \*\*\*/",
            r"#define HAVE.*PROG_TYPE",
            r"/\*\*\* eBPF map types \*\*\*/",
            r"#define HAVE.*MAP_TYPE",
            r"/\*\*\* eBPF helper functions \*\*\*/",
            r"#define HAVE.*HELPER",
            r"/\*\*\* eBPF misc features \*\*\*/",
        ]

        res = bpftool(["feature", "probe", "macros"])
        for pattern in expected_patterns:
            self.assertRegex(res, pattern)

    def assertStringsPresent(self, text, patterns):
        pos = 0
        for i, pat in enumerate(patterns):
            m = text.find(pat, pos)
            if m == -1:
                with io.StringIO() as msg:
                    print("Can't find expected string:", file=msg)
                    for s in patterns[0:i]:
                        print("    MATCHED: " + s, file=msg)
                    print("NOT MATCHED: " + pat, file=msg)
                    print("", file=msg)
                    print("Searching in:", file=msg)
                    print(text, file=msg)
                    self.fail(msg.getvalue())
            pos += len(pat)

    # Load a small program that has some context types in it's BTF,
    # verify that "bpftool btf dump file ... format c" emits
    # preserve_static_offset attribute.
    def test_c_dump_preserve_static_offset_present(self):
        res = bpftool(["btf", "dump", "file", DUMMY_SK_BUFF_USER_OBJ, "format", "c"])
        self.assertStringsPresent(res, [
            "#if !defined(BPF_NO_PRESERVE_STATIC_OFFSET) && " +
              "__has_attribute(preserve_static_offset)",
            "#pragma clang attribute push " +
              "(__attribute__((preserve_static_offset)), apply_to = record)",
            "struct __sk_buff;",
            "struct bpf_sock;",
            "#pragma clang attribute pop",
            "#endif /* BPF_NO_PRESERVE_STATIC_OFFSET */",
            "#pragma clang attribute push " +
              "(__attribute__((preserve_access_index)), apply_to = record)",
            "struct __sk_buff {",
        ])

    # Load a small program that has no context types in it's BTF,
    # verify that "bpftool btf dump file ... format c" does not emit
    # preserve_static_offset attribute.
    def test_c_dump_no_preserve_static_offset(self):
        res = bpftool(["btf", "dump", "file", DUMMY_NO_CONTEXT_BTF_OBJ, "format", "c"])
        self.assertNotRegex(res, "preserve_static_offset")
        self.assertStringsPresent(res, [
            "preserve_access_index",
            "typedef unsigned int __u32;"
        ])
