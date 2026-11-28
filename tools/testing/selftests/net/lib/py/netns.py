# SPDX-License-Identifier: GPL-2.0

import ctypes
import os
import random
import string
import subprocess
import time
from pathlib import Path

from .utils import ip

libc = ctypes.CDLL('libc.so.6', use_errno=True)


class NetNS:
    def __init__(self, name=None):
        self.name = None
        if not name:
            name = ''.join(random.choice(string.ascii_lowercase) for _ in range(8))
        ip('netns add ' + name)
        self.name = name

    def __del__(self):
        if self.name:
            ip('netns del ' + self.name)
            self.name = None

    def __enter__(self):
        return self

    def __exit__(self, ex_type, ex_value, ex_tb):
        self.__del__()

    def __str__(self):
        return self.name

    def __repr__(self):
        return f"NetNS({self.name})"


class UserNetNS:
    """Network namespace owned by a non-init user namespace."""

    def __init__(self):
        self.name = ''.join(
            random.choice(string.ascii_lowercase) for _ in range(8))
        self.user_ns_path = f"/run/userns/{self.name}"
        self.net_ns_path = f"/run/netns/{self.name}"
        self._user_mounted = False
        self._net_mounted = False

        os.makedirs("/run/userns", exist_ok=True)
        os.makedirs("/run/netns", exist_ok=True)

        Path(self.user_ns_path).touch()
        Path(self.net_ns_path).touch()

        with subprocess.Popen(
                ["unshare", "--user", "--net", "--map-root-user",
                 "sleep", "infinity"]) as proc:
            try:
                pid = proc.pid
                init_user = os.readlink("/proc/self/ns/user")
                for _ in range(200):
                    try:
                        if os.readlink(f"/proc/{pid}/ns/user") != init_user:
                            break
                    except OSError:
                        pass
                    time.sleep(0.01)
                else:
                    raise RuntimeError("unshare child did not create userns")

                subprocess.run(["mount", "--bind", f"/proc/{pid}/ns/user",
                                self.user_ns_path], check=True)
                self._user_mounted = True
                subprocess.run(["mount", "--bind", f"/proc/{pid}/ns/net",
                                self.net_ns_path], check=True)
                self._net_mounted = True
            finally:
                proc.kill()

    def __del__(self):
        if self._net_mounted:
            subprocess.run(["umount", self.net_ns_path], check=False)
            self._net_mounted = False
        if self._user_mounted:
            subprocess.run(["umount", self.user_ns_path], check=False)
            self._user_mounted = False
        for path in (self.net_ns_path, self.user_ns_path):
            try:
                os.unlink(path)
            except OSError:
                pass

    def __enter__(self):
        return self

    def __exit__(self, ex_type, ex_value, ex_tb):
        self.__del__()

    def __str__(self):
        return self.name

    def __repr__(self):
        return f"UserNetNS({self.name})"


class NetNSEnter:
    def __init__(self, ns_name):
        self.ns_path = f"/run/netns/{ns_name}"

    @staticmethod
    def _setns(fd):
        if libc.setns(fd, 0) == -1:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))

    def __enter__(self):
        self.saved = open("/proc/thread-self/ns/net")
        try:
            with open(self.ns_path) as ns_file:
                self._setns(ns_file.fileno())
        except BaseException:
            self.saved.close()
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            self._setns(self.saved.fileno())
        finally:
            self.saved.close()
