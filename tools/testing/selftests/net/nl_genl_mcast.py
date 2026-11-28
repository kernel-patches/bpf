#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

"""
Tests for joining Generic Netlink multicast groups that no family owns.
"""

import os
import socket
import struct

from lib.py import ksft_run, ksft_exit, ksft_eq, ksft_raises
from lib.py import KsftSkipEx, NlctrlFamily, NlError, cmd

NETLINK_GENERIC = 16
SOL_NETLINK = 270
NETLINK_ADD_MEMBERSHIP = 1
NETLINK_LIST_MEMBERSHIPS = 9
# include/uapi/linux/nsfs.h
NET_NS_INIT_INO = 0xEFFFFFF9


def _groups(fam):
    """Return the multicast groups of a family as {name: id}."""
    return {g['name']: g['id']
            for grp in fam.get('mcast-groups', []) for g in grp.values()}


def _free_ids(ctrl):
    """Return the IDs in 1..32 that no family owns."""
    # Outside init_net, the dump skips the families that are not netnsok,
    # but their groups are still owned.
    if os.stat('/proc/self/ns/net').st_ino != NET_NS_INIT_INO:
        raise KsftSkipEx("not in the initial network namespace, "
                         "or the kernel is older than v6.17")

    owned = set()
    for fam in ctrl.getfamily({}, dump=True):
        owned.update(_groups(fam).values())
    free = [gid for gid in range(1, 33) if gid not in owned]
    if not free:
        raise KsftSkipEx("no free group ID in 1..32")
    return free


def _sock():
    return socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)


def _members(sk):
    # The returned length can be larger than what the kernel copied.
    buf = sk.getsockopt(SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS, 64)[:64]
    # An array of u32 in host byte order
    words = struct.unpack(f'={len(buf) // 4}I', buf)
    return sum(w << (32 * i) for i, w in enumerate(words))


def _bit(gid):
    return 1 << (gid - 1)


def _notify_id(ctrl):
    return _groups(ctrl.getfamily({'family-name': 'nlctrl'}))['notify']


def join_free(ctrl) -> None:
    """setsockopt() on an ID no family owns fails with ENOENT."""
    with _sock() as sk:
        sk.bind((0, 0))
        for gid in _free_ids(ctrl):
            # ENOENT
            with ksft_raises(FileNotFoundError):
                sk.setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, gid)

        notify = _notify_id(ctrl)
        sk.setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, notify)
        ksft_eq(_members(sk), _bit(notify))


def bind_mask(ctrl) -> None:
    """bind() skips the IDs no family owns and joins the others."""
    free = sum(_bit(gid) for gid in _free_ids(ctrl))
    notify = _notify_id(ctrl)

    with _sock() as sk:
        sk.bind((0, free))
        ksft_eq(_members(sk), 0)

    with _sock() as sk:
        sk.bind((0, free | _bit(notify)))
        ksft_eq(_members(sk), _bit(notify))


def _unload_drop_monitor():
    """Unload drop_monitor, so that the next run can load it again."""
    try:
        cmd("modprobe -q -r drop_monitor", fail=False)
    except OSError:
        # No modprobe in PATH
        pass


def bind_before_family(ctrl) -> None:
    """A free ID joined with bind() stays unjoined when a family takes it."""
    names = [fam['family-name'] for fam in ctrl.getfamily({}, dump=True)]
    if 'NET_DM' in names:
        raise KsftSkipEx("NET_DM is already registered")

    free = _free_ids(ctrl)
    with _sock() as sk:
        sk.bind((0, sum(_bit(gid) for gid in free)))

        # Looking up the family loads drop_monitor.
        try:
            ids = _groups(ctrl.getfamily({'family-name': 'NET_DM'}))
        except NlError as e:
            raise KsftSkipEx("drop_monitor is not available") from e

        try:
            if not any(gid in free for gid in ids.values()):
                raise KsftSkipEx("NET_DM got no group ID that was free")

            for name, gid in ids.items():
                ksft_eq(_members(sk) & _bit(gid), 0,
                        comment=f"member of NET_DM {name}")
        finally:
            _unload_drop_monitor()


def main() -> None:
    """ Ksft boiler plate main """
    ctrl = NlctrlFamily()
    ksft_run([join_free, bind_mask, bind_before_family], args=(ctrl, ))
    ksft_exit()


if __name__ == "__main__":
    main()
