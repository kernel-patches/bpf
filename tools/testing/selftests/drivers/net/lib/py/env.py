# SPDX-License-Identifier: GPL-2.0

import os
import shlex
from pathlib import Path
from lib.py import ip
from lib.py import NetNS, NetdevSimDev
from .remote import Remote


def _load_env_file(src_path):
    env = os.environ.copy()

    src_dir = Path(src_path).parent.resolve()
    if not (src_dir / "net.config").exists():
        return env

    lexer = shlex.shlex(open((src_dir / "net.config").as_posix(), 'r').read())
    k = None
    for token in lexer:
        if k is None:
            k = token
            env[k] = ""
        elif token == "=":
            pass
        else:
            env[k] = token
            k = None
    return env


class NetDrvEnv:
    """
    Class for a single NIC / host env, with no remote end
    """
    def __init__(self, src_path):
        self._ns = None

        self.env = _load_env_file(src_path)

        if 'NETIF' in self.env:
            self.dev = ip("link show dev " + self.env['NETIF'], json=True)[0]
        else:
            self._ns = NetdevSimDev()
            self.dev = self._ns.nsims[0].dev
        self.ifindex = self.dev['ifindex']

    def __enter__(self):
        return self

    def __exit__(self, ex_type, ex_value, ex_tb):
        """
        __exit__ gets called at the end of a "with" block.
        """
        self.__del__()

    def __del__(self):
        if self._ns:
            self._ns.remove()
            self._ns = None


class NetDrvEpEnv:
    """
    Class for an environment with a local device and "remote endpoint"
    which can be used to send traffic in.

    For local testing it creates two network namespaces and a pair
    of netdevsim devices.
    """

    # Network prefixes used for local tests
    nsim_v4_pfx = "192.0.2."
    nsim_v6_pfx = "2001:db8::"

    def __init__(self, src_path):

        self.env = _load_env_file(src_path)

        # Things we try to destroy
        self.remote = None
        # These are for local testing state
        self._netns = None
        self._ns = None
        self._ns_peer = None

        if "NETIF" in self.env:
            self.dev = ip("link show dev " + self.env['NETIF'], json=True)[0]

            self.v4 = self.env.get("LOCAL_V4")
            self.v6 = self.env.get("LOCAL_V6")
            self.remote_v4 = self.env.get("REMOTE_V4")
            self.remote_v6 = self.env.get("REMOTE_V6")
            kind = self.env["REMOTE_TYPE"]
            args = self.env["REMOTE_ARGS"]
        else:
            self.create_local()

            self.dev = self._ns.nsims[0].dev

            self.v4 = self.nsim_v4_pfx + "1"
            self.v6 = self.nsim_v6_pfx + "1"
            self.remote_v4 = self.nsim_v4_pfx + "2"
            self.remote_v6 = self.nsim_v6_pfx + "2"
            kind = "netns"
            args = self._netns.name

        self.remote = Remote(kind, args, src_path)

        self.addr = self.v6 if self.v6 else self.v4
        self.remote_addr = self.remote_v6 if self.remote_v6 else self.remote_v4

        self.addr_ipver = "6" if self.v6 else "4"
        # Bracketed addresses, some commands need IPv6 to be inside []
        self.baddr = f"[{self.v6}]" if self.v6 else self.v4
        self.remote_baddr = f"[{self.remote_v6}]" if self.remote_v6 else self.remote_v4

        self.ifname = self.dev['ifname']
        self.ifindex = self.dev['ifindex']

    def create_local(self):
        self._netns = NetNS()
        self._ns = NetdevSimDev()
        self._ns_peer = NetdevSimDev(ns=self._netns)

        with open("/proc/self/ns/net") as nsfd0, \
             open("/var/run/netns/" + self._netns.name) as nsfd1:
            ifi0 = self._ns.nsims[0].ifindex
            ifi1 = self._ns_peer.nsims[0].ifindex
            NetdevSimDev.ctrl_write('link_device',
                                    f'{nsfd0.fileno()}:{ifi0} {nsfd1.fileno()}:{ifi1}')

        ip(f"   addr add dev {self._ns.nsims[0].ifname} {self.nsim_v4_pfx}1/24")
        ip(f"-6 addr add dev {self._ns.nsims[0].ifname} {self.nsim_v6_pfx}1/64 nodad")
        ip(f"   link set dev {self._ns.nsims[0].ifname} up")

        ip(f"   addr add dev {self._ns_peer.nsims[0].ifname} {self.nsim_v4_pfx}2/24", ns=self._netns)
        ip(f"-6 addr add dev {self._ns_peer.nsims[0].ifname} {self.nsim_v6_pfx}2/64 nodad", ns=self._netns)
        ip(f"   link set dev {self._ns_peer.nsims[0].ifname} up", ns=self._netns)

    def __enter__(self):
        return self

    def __exit__(self, ex_type, ex_value, ex_tb):
        """
        __exit__ gets called at the end of a "with" block.
        """
        self.__del__()

    def __del__(self):
        if self._ns:
            self._ns.remove()
            self._ns = None
        if self._ns_peer:
            self._ns_peer.remove()
            self._ns_peer = None
        if self._netns:
            del self._netns
            self._netns = None
        if self.remote:
            del self.remote
            self.remote = None
