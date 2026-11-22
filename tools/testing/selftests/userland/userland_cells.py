# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2026 Opinsys Oy

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
import ctypes
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
import errno
import os
import platform
import signal
import sys
from types import TracebackType
from typing import Any, ClassVar, Final, NoReturn

HOST_RUNTIME_ENTRIES: Final[tuple[str, ...]] = (
    "usr",
    "bin",
    "sbin",
    "lib",
    "lib32",
    "lib64",
    "libx32",
    "etc",
    "opt",
    "nix",
)


class UserlandFlag(IntFlag):
    NONE = 0
    KILL_ON_CLOSE = 0x00000001
    CLOSE_ON_EXEC = 0x00000002
    DEFAULT = KILL_ON_CLOSE | CLOSE_ON_EXEC
    ALL = KILL_ON_CLOSE | CLOSE_ON_EXEC


class CloneFlag(IntFlag):
    NONE = 0
    NEWTIME = 0x00000080
    VM = 0x00000100
    FS = 0x00000200
    FILES = 0x00000400
    SIGHAND = 0x00000800
    PIDFD = 0x00001000
    VFORK = 0x00004000
    PARENT = 0x00008000
    THREAD = 0x00010000
    NEWNS = 0x00020000
    SYSVSEM = 0x00040000
    NEWCGROUP = 0x02000000
    NEWUTS = 0x04000000
    NEWIPC = 0x08000000
    NEWUSER = 0x10000000
    NEWPID = 0x20000000
    NEWNET = 0x40000000
    CLEAR_SIGHAND = 1 << 32
    INTO_CGROUP = 1 << 33
    AUTOREAP = 1 << 34
    NNP = 1 << 35
    PIDFD_AUTOKILL = 1 << 36
    EMPTY_MNTNS = 1 << 37
    INTO_USERLAND = 1 << 38


class AtFlag(IntFlag):
    NONE = 0
    EMPTY_PATH = 0x1000
    RECURSIVE = 0x8000


class OpenTreeFlag(IntFlag):
    CLONE = 1 << 0
    CLOEXEC = os.O_CLOEXEC
    RECURSIVE = 0x8000


class MoveMountFlag(IntFlag):
    F_EMPTY_PATH = 0x00000004
    T_EMPTY_PATH = 0x00000040
    T_MNTNS = 0x00000080
    SET_GROUP = 0x00000100
    BENEATH = 0x00000200
    CLONE = 0x00000400


class UsernsFlag(IntFlag):
    NONE = 0
    SETGROUPS_ALLOWED = 1 << 0


class MountAttrFlag(IntFlag):
    NONE = 0
    RDONLY = 0x00000001
    NOSUID = 0x00000002
    NODEV = 0x00000004


class MountFlag(IntFlag):
    REC = 0x4000
    PRIVATE = 1 << 18
    SLAVE = 1 << 19
    SHARED = 1 << 20


class UmountFlag(IntFlag):
    NONE = 0
    DETACH = 2


class ResolveFlag(IntFlag):
    NONE = 0
    IN_ROOT = 0x10


class FsconfigCmd(IntEnum):
    SET_FLAG = 0
    SET_STRING = 1
    CMD_CREATE = 6
    SET_USERLAND = 9


class PrctlOp(IntEnum):
    GET_DUMPABLE = 3
    SET_DUMPABLE = 4
    SET_KEEPCAPS = 8
    GET_NO_NEW_PRIVS = 39


class WaitIdType(IntEnum):
    ALL = 0
    PID = 1
    PGID = 2
    PIDFD = 3
    USERLAND = 4


class CloneArgs(ctypes.Structure):
    SIZE_VER2: ClassVar[int] = 88
    SIZE_VER3: ClassVar[int] = 96

    flags: int
    pidfd: int
    child_tid: int
    parent_tid: int
    exit_signal: int
    stack: int
    stack_size: int
    tls: int
    set_tid: int
    set_tid_size: int
    cgroup: int
    userland: int
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("pidfd", ctypes.c_uint64),
        ("child_tid", ctypes.c_uint64),
        ("parent_tid", ctypes.c_uint64),
        ("exit_signal", ctypes.c_uint64),
        ("stack", ctypes.c_uint64),
        ("stack_size", ctypes.c_uint64),
        ("tls", ctypes.c_uint64),
        ("set_tid", ctypes.c_uint64),
        ("set_tid_size", ctypes.c_uint64),
        ("cgroup", ctypes.c_uint64),
        ("userland", ctypes.c_uint64),
    ]


class OpenHow(ctypes.Structure):
    flags: int
    mode: int
    resolve: int
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


class UsernsIdmapExtent(ctypes.Structure):
    first: int
    lower_first: int
    count: int
    reserved: int
    _fields_ = [
        ("first", ctypes.c_uint32),
        ("lower_first", ctypes.c_uint32),
        ("count", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
    ]


class CapHeader(ctypes.Structure):
    VERSION_3: ClassVar[int] = 0x20080522

    version: int
    pid: int
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("pid", ctypes.c_int32),
    ]


class CapData(ctypes.Structure):
    effective: int
    permitted: int
    inheritable: int
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


class UsernsIdmap(ctypes.Structure):
    SIZE_VER0: ClassVar[int] = 40

    nr_uid_extents: int
    nr_gid_extents: int
    nr_projid_extents: int
    reserved: int
    uid_extents: int
    gid_extents: int
    projid_extents: int
    _fields_ = [
        ("nr_uid_extents", ctypes.c_uint32),
        ("nr_gid_extents", ctypes.c_uint32),
        ("nr_projid_extents", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("uid_extents", ctypes.c_uint64),
        ("gid_extents", ctypes.c_uint64),
        ("projid_extents", ctypes.c_uint64),
    ]


class Sys:
    AT_FDCWD: Final[int] = -100
    FSOPEN_CLOEXEC: Final[int] = 0x00000001
    FSMOUNT_CLOEXEC: Final[int] = 0x00000001
    CAP_SETGID: Final[int] = 6
    CAP_SETUID: Final[int] = 7
    _WIDE_IOC_PREFIXES: Final[tuple[str, ...]] = (
        "alpha",
        "mips",
        "powerpc",
        "ppc",
        "sparc",
    )

    @classmethod
    def _is_wide_ioc_arch(cls) -> bool:
        return platform.machine().lower().startswith(cls._WIDE_IOC_PREFIXES)

    @classmethod
    def ioc(cls, direction: int, magic: int, nr: int, size: int) -> int:
        sizebits = 13 if cls._is_wide_ioc_arch() else 14
        typeshift = 8
        sizeshift = 16
        dirshift = sizeshift + sizebits
        return (
            (direction << dirshift)
            | (magic << typeshift)
            | nr
            | (size << sizeshift)
        )

    @classmethod
    def io(cls, magic: int, nr: int) -> int:
        none_dir = 1 if cls._is_wide_ioc_arch() else 0
        return cls.ioc(none_dir, magic, nr, 0)

    @staticmethod
    def _build_syscall_numbers() -> dict[str, int]:
        mach = platform.machine().lower()
        ptr_size = ctypes.sizeof(ctypes.c_void_p)
        multiarch = getattr(sys.implementation, "_multiarch", "")
        arch_legacy: dict[str, int]

        if mach.startswith("alpha"):
            base = 110
            arch_legacy = {
                "pivot_root": 374,
                "umount2": 22,
                "waitid": 438,
                "execveat": 513,
            }
        elif mach.startswith("mips"):
            if ptr_size == 8:
                base = 5000
                arch_legacy = {
                    "pivot_root": 5151,
                    "umount2": 5161,
                    "waitid": 5237,
                    "execveat": 5316,
                }
            elif "abin32" in multiarch:
                base = 6000
                arch_legacy = {
                    "pivot_root": 6151,
                    "umount2": 6161,
                    "waitid": 6241,
                    "execveat": 6320,
                }
            else:
                base = 4000
                arch_legacy = {
                    "pivot_root": 4216,
                    "umount2": 4052,
                    "waitid": 4278,
                    "execveat": 4356,
                }
        elif mach == "x86_64" and ptr_size == 4:
            base = 0x40000000
            arch_legacy = {
                "pivot_root": base + 155,
                "umount2": base + 166,
                "waitid": base + 529,
                "execveat": base + 545,
            }
        else:
            base = 0
            asm_generic = {
                "pivot_root": 41,
                "umount2": 39,
                "waitid": 95,
                "execveat": 281,
            }
            if mach == "x86_64":
                arch_legacy = {
                    "pivot_root": 155,
                    "umount2": 166,
                    "waitid": 247,
                    "execveat": 322,
                }
            elif mach in ("i386", "i486", "i586", "i686"):
                arch_legacy = {
                    "pivot_root": 217,
                    "umount2": 52,
                    "waitid": 284,
                    "execveat": 358,
                }
            elif mach in ("aarch64", "arm64") and ptr_size == 8:
                arch_legacy = asm_generic
            elif mach.startswith(("arm", "aarch64")):
                arch_legacy = {
                    "pivot_root": 218,
                    "umount2": 52,
                    "waitid": 280,
                    "execveat": 387,
                }
            elif mach.startswith(("ppc", "powerpc")):
                arch_legacy = {
                    "pivot_root": 203,
                    "umount2": 52,
                    "waitid": 272,
                    "execveat": 362,
                }
            elif mach.startswith("s390"):
                arch_legacy = {
                    "pivot_root": 217,
                    "umount2": 52,
                    "waitid": 281,
                    "execveat": 354,
                }
            elif mach.startswith("sparc"):
                arch_legacy = {
                    "pivot_root": 146,
                    "umount2": 45,
                    "waitid": 279,
                    "execveat": 350,
                }
            elif mach.startswith(("parisc", "hppa")):
                arch_legacy = {
                    "pivot_root": 67,
                    "umount2": 52,
                    "waitid": 235,
                    "execveat": 342,
                }
            elif mach == "m68k":
                arch_legacy = {
                    "pivot_root": 217,
                    "umount2": 52,
                    "waitid": 277,
                    "execveat": 355,
                }
            elif mach.startswith("microblaze"):
                arch_legacy = {
                    "pivot_root": 217,
                    "umount2": 52,
                    "waitid": 284,
                    "execveat": 388,
                }
            elif mach.startswith("sh"):
                arch_legacy = {
                    "pivot_root": 217,
                    "umount2": 52,
                    "waitid": 284,
                    "execveat": 376,
                }
            elif mach == "xtensa":
                arch_legacy = {
                    "pivot_root": 175,
                    "umount2": 171,
                    "waitid": 122,
                    "execveat": 341,
                }
            else:
                arch_legacy = asm_generic

        nums: dict[str, int] = {
            "pidfd_send_signal": base + 424,
            "open_tree": base + 428,
            "move_mount": base + 429,
            "fsopen": base + 430,
            "fsconfig": base + 431,
            "fsmount": base + 432,
            "clone3": base + 435,
            "openat2": base + 437,
            "userns_set_idmap": base + 473,
            "userland_open": base + 474,
        }
        nums.update(arch_legacy)
        return nums

    _NR: ClassVar[dict[str, int]]
    _LIBC: ClassVar[ctypes.CDLL]

    @staticmethod
    def _os_err() -> NoReturn:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))

    @staticmethod
    def _cstr(val: str | bytes) -> bytes:
        return val if isinstance(val, bytes) else os.fsencode(val)

    @classmethod
    def syscall(cls, name: str, *args: Any) -> int:
        ret: int = cls._LIBC.syscall(ctypes.c_long(cls._NR[name]), *args)
        if ret < 0:
            cls._os_err()
        return int(ret)

    @classmethod
    def ioctl(cls, fd: int, cmd: int, arg: int = 0) -> int:
        ret: int = cls._LIBC.ioctl(
            ctypes.c_int(fd), ctypes.c_ulong(int(cmd)), ctypes.c_ulong(arg)
        )
        if ret < 0:
            cls._os_err()
        return int(ret)

    @classmethod
    def fsopen(cls, fsname: str | bytes, flags: int = FSOPEN_CLOEXEC) -> int:
        return cls.syscall(
            "fsopen", ctypes.c_char_p(cls._cstr(fsname)), ctypes.c_uint(flags)
        )

    @classmethod
    def fsconfig(
        cls,
        fsfd: int,
        cmd: FsconfigCmd,
        key: str | bytes | None = None,
        value: str | bytes | None = None,
        aux: int = 0,
    ) -> None:
        k_ptr = (
            ctypes.c_char_p(cls._cstr(key))
            if key is not None
            else ctypes.c_void_p(0)
        )
        v_ptr = (
            ctypes.c_char_p(cls._cstr(value))
            if value is not None
            else ctypes.c_void_p(0)
        )
        cls.syscall(
            "fsconfig",
            ctypes.c_int(fsfd),
            ctypes.c_uint(int(cmd)),
            k_ptr,
            v_ptr,
            ctypes.c_int(aux),
        )

    @classmethod
    def fsmount(
        cls,
        fsfd: int,
        flags: int = FSMOUNT_CLOEXEC,
        attr_flags: MountAttrFlag = MountAttrFlag.NONE,
    ) -> int:
        return cls.syscall(
            "fsmount",
            ctypes.c_int(fsfd),
            ctypes.c_uint(flags),
            ctypes.c_uint(int(attr_flags)),
        )

    @classmethod
    def open_tree(
        cls, dfd: int, path: str | bytes, flags: OpenTreeFlag
    ) -> int:
        return cls.syscall(
            "open_tree",
            ctypes.c_int(dfd),
            ctypes.c_char_p(cls._cstr(path)),
            ctypes.c_uint(int(flags)),
        )

    @classmethod
    def move_mount(
        cls,
        from_dfd: int,
        from_path: str | bytes,
        to_dfd: int,
        to_path: str | bytes,
        flags: MoveMountFlag,
    ) -> None:
        cls.syscall(
            "move_mount",
            ctypes.c_int(from_dfd),
            ctypes.c_char_p(cls._cstr(from_path)),
            ctypes.c_int(to_dfd),
            ctypes.c_char_p(cls._cstr(to_path)),
            ctypes.c_uint(int(flags)),
        )

    @classmethod
    def openat2(
        cls,
        dfd: int,
        path: str | bytes,
        flags: int,
        mode: int = 0,
        resolve: ResolveFlag = ResolveFlag.NONE,
    ) -> int:
        how = OpenHow(flags=flags, mode=mode, resolve=int(resolve))
        return cls.syscall(
            "openat2",
            ctypes.c_int(dfd),
            ctypes.c_char_p(cls._cstr(path)),
            ctypes.byref(how),
            ctypes.c_size_t(ctypes.sizeof(how)),
        )

    @classmethod
    def execveat(
        cls,
        dfd: int,
        path: str | bytes,
        argv: Sequence[str],
        envp: Mapping[str, str] | Sequence[str] | None = None,
        flags: AtFlag = AtFlag.NONE,
    ) -> NoReturn:
        c_argv = (ctypes.c_char_p * (len(argv) + 1))(
            *[cls._cstr(a) for a in argv], None
        )
        if envp is None:
            env_items = [f"{k}={v}" for k, v in os.environ.items()]
        elif isinstance(envp, Mapping):
            env_items = [f"{k}={v}" for k, v in envp.items()]
        else:
            env_items = list(envp)
        c_envp = (ctypes.c_char_p * (len(env_items) + 1))(
            *[cls._cstr(e) for e in env_items], None
        )
        cls.syscall(
            "execveat",
            ctypes.c_int(dfd),
            ctypes.c_char_p(cls._cstr(path)),
            c_argv,
            c_envp,
            ctypes.c_int(int(flags)),
        )
        cls._os_err()

    @classmethod
    def pivot_root(cls, new_root: str | bytes, put_old: str | bytes) -> None:
        cls.syscall(
            "pivot_root",
            ctypes.c_char_p(cls._cstr(new_root)),
            ctypes.c_char_p(cls._cstr(put_old)),
        )

    @classmethod
    def umount2(
        cls, target: str | bytes, flags: UmountFlag = UmountFlag.NONE
    ) -> None:
        cls.syscall(
            "umount2",
            ctypes.c_char_p(cls._cstr(target)),
            ctypes.c_int(int(flags)),
        )

    @classmethod
    def set_mount_propagation(
        cls,
        target: str | bytes = "/",
        flags: MountFlag = MountFlag.REC | MountFlag.PRIVATE,
    ) -> None:
        ret: int = cls._LIBC.mount(
            ctypes.c_char_p(b"none"),
            ctypes.c_char_p(cls._cstr(target)),
            ctypes.c_void_p(0),
            ctypes.c_ulong(int(flags)),
            ctypes.c_void_p(0),
        )
        if ret < 0:
            cls._os_err()

    @classmethod
    def setgroups_empty(cls) -> None:
        ret: int = cls._LIBC.setgroups(ctypes.c_size_t(0), ctypes.c_void_p(0))
        if ret < 0:
            cls._os_err()

    @classmethod
    def drop_to_setid_helper(cls, uid: int) -> None:
        cls.prctl(PrctlOp.SET_KEEPCAPS, 1)
        try:
            cls.setgroups_empty()
        except OSError as exc:
            if exc.errno != errno.EPERM:
                raise
        os.setresgid(uid, uid, uid)
        os.setresuid(uid, uid, uid)
        hdr = CapHeader(version=CapHeader.VERSION_3, pid=0)
        mask = (1 << cls.CAP_SETGID) | (1 << cls.CAP_SETUID)
        data = (CapData * 2)(
            CapData(effective=mask, permitted=mask, inheritable=0),
            CapData(effective=0, permitted=0, inheritable=0),
        )
        ret: int = cls._LIBC.capset(ctypes.byref(hdr), ctypes.byref(data))
        if ret < 0:
            cls._os_err()
        cls.prctl(PrctlOp.SET_DUMPABLE, 1)

    @classmethod
    def prctl(
        cls,
        option: PrctlOp,
        arg2: int = 0,
        arg3: int = 0,
        arg4: int = 0,
        arg5: int = 0,
    ) -> int:
        ret: int = cls._LIBC.prctl(
            ctypes.c_int(int(option)),
            ctypes.c_ulong(arg2),
            ctypes.c_ulong(arg3),
            ctypes.c_ulong(arg4),
            ctypes.c_ulong(arg5),
        )
        if ret < 0:
            cls._os_err()
        return int(ret)

    @classmethod
    def clone3(cls, args: CloneArgs, size: int | None = None) -> int:
        actual_size = ctypes.sizeof(args) if size is None else size
        sys.stdout.flush()
        sys.stderr.flush()
        return cls.syscall(
            "clone3", ctypes.byref(args), ctypes.c_size_t(actual_size)
        )

    @staticmethod
    def _extent_array(
        extents: Sequence[tuple[int, int, int]],
    ) -> ctypes.Array[UsernsIdmapExtent] | None:
        if not extents:
            return None
        arr_t = UsernsIdmapExtent * len(extents)
        return arr_t(
            *[
                UsernsIdmapExtent(
                    first=first, lower_first=lower, count=count, reserved=0
                )
                for first, lower, count in extents
            ]
        )

    @classmethod
    def pidfd_send_signal(
        cls,
        pidfd: int,
        sig: int,
        info_addr: int = 0,
        flags: int = 0,
    ) -> None:
        cls.syscall(
            "pidfd_send_signal",
            ctypes.c_int(pidfd),
            ctypes.c_int(sig),
            ctypes.c_void_p(info_addr),
            ctypes.c_uint(flags),
        )

    @classmethod
    def waitid_raw(
        cls,
        which: int,
        upid: int,
        infop_addr: int,
        options: int,
        ru_addr: int = 0,
    ) -> None:
        cls.syscall(
            "waitid",
            ctypes.c_int(which),
            ctypes.c_int(upid),
            ctypes.c_void_p(infop_addr),
            ctypes.c_int(options),
            ctypes.c_void_p(ru_addr),
        )

    @classmethod
    def userns_set_idmap_raw(
        cls,
        userns_fd: int,
        map_addr: int,
        size: int = UsernsIdmap.SIZE_VER0,
        flags: int = 0,
    ) -> None:
        cls.syscall(
            "userns_set_idmap",
            ctypes.c_int(userns_fd),
            ctypes.c_void_p(map_addr),
            ctypes.c_size_t(size),
            ctypes.c_uint(flags),
        )

    @classmethod
    def set_userns_idmap(
        cls,
        userns_fd: int,
        uid_extents: Sequence[tuple[int, int, int]] = (),
        gid_extents: Sequence[tuple[int, int, int]] = (),
        projid_extents: Sequence[tuple[int, int, int]] = (),
        *,
        reserved: int = 0,
        size: int | None = None,
        flags: UsernsFlag | int = UsernsFlag.NONE,
    ) -> None:
        u_arr = cls._extent_array(uid_extents)
        g_arr = cls._extent_array(gid_extents)
        p_arr = cls._extent_array(projid_extents)
        req = UsernsIdmap(
            nr_uid_extents=len(uid_extents),
            nr_gid_extents=len(gid_extents),
            nr_projid_extents=len(projid_extents),
            reserved=reserved,
            uid_extents=ctypes.addressof(u_arr) if u_arr is not None else 0,
            gid_extents=ctypes.addressof(g_arr) if g_arr is not None else 0,
            projid_extents=ctypes.addressof(p_arr) if p_arr is not None else 0,
        )
        cls.userns_set_idmap_raw(
            userns_fd,
            ctypes.addressof(req),
            ctypes.sizeof(req) if size is None else size,
            int(flags),
        )


Sys._NR = Sys._build_syscall_numbers()
Sys._LIBC = ctypes.CDLL(None, use_errno=True)
Sys._LIBC.syscall.restype = ctypes.c_long


class Ioctl(IntEnum):
    USERLAND_GET_NSFD = Sys.io(0xB9, 0x01)
    USERLAND_SHARE_NSFD = Sys.io(0xB9, 0x02)
    NS_GET_USERNS = Sys.io(0xB7, 0x01)
    NS_GET_PARENT = Sys.io(0xB7, 0x02)
    NS_GET_NSTYPE = Sys.io(0xB7, 0x03)


@dataclass(frozen=True)
class WaitResult:
    pid: int
    status: int = 0
    code: int = 0
    uid: int = 0

    @property
    def exit_code(self) -> int | None:
        if self.pid <= 0:
            return None
        if self.code == os.CLD_EXITED:
            return self.status
        if self.code in (os.CLD_KILLED, os.CLD_DUMPED):
            return -self.status
        return os.waitstatus_to_exitcode(self.status)


class Userland:
    fd: int

    def __init__(
        self,
        flags: UserlandFlag | int = UserlandFlag.DEFAULT,
        *,
        fd: int | None = None,
    ) -> None:
        if fd is not None:
            self.fd = fd
        else:
            self.fd = Sys.syscall("userland_open", ctypes.c_uint(int(flags)))

    @classmethod
    def from_fd(cls, fd: int) -> Userland:
        return cls(fd=fd)

    def fileno(self) -> int:
        return self.fd

    def __enter__(self) -> Userland:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        if self.fd >= 0:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = -1

    def get_nsfd(self, nstype: CloneFlag | int) -> int:
        return Sys.ioctl(self.fd, Ioctl.USERLAND_GET_NSFD, int(nstype))

    def share_nsfd(self, nsfd: int) -> None:
        Sys.ioctl(self.fd, Ioctl.USERLAND_SHARE_NSFD, nsfd)

    def set_idmap(
        self,
        uid_extents: Sequence[tuple[int, int, int]] = (),
        gid_extents: Sequence[tuple[int, int, int]] = (),
        projid_extents: Sequence[tuple[int, int, int]] = (),
        *,
        flags: UsernsFlag | int = UsernsFlag.NONE,
    ) -> None:
        userns_fd = self.get_nsfd(CloneFlag.NEWUSER)
        try:
            Sys.set_userns_idmap(
                userns_fd,
                uid_extents=uid_extents,
                gid_extents=gid_extents,
                projid_extents=projid_extents,
                flags=flags,
            )
        finally:
            os.close(userns_fd)

    def map_self_ugid(self) -> None:
        self.set_idmap(
            uid_extents=((0, os.geteuid(), 1),),
            gid_extents=((0, os.getegid(), 1),),
        )

    def wait(self, flags: int = 0) -> WaitResult:
        res = os.waitid(int(WaitIdType.USERLAND), self.fd, os.WEXITED | flags)
        if res is None:
            return WaitResult(pid=0)
        return WaitResult(
            pid=int(res.si_pid),
            status=int(res.si_status),
            code=int(res.si_code),
            uid=int(res.si_uid),
        )

    def kill(self, sig: signal.Signals | int) -> None:
        Sys.pidfd_send_signal(self.fd, int(sig))

    def clone_into(
        self,
        extra_flags: CloneFlag = CloneFlag.NONE,
        exit_signal: int = int(signal.SIGCHLD),
    ) -> tuple[int, int]:
        pidfd_cell = ctypes.c_int(-1)
        args = CloneArgs()
        args.flags = int(CloneFlag.INTO_USERLAND | extra_flags)
        args.exit_signal = exit_signal
        args.userland = self.fd & 0xFFFFFFFFFFFFFFFF
        if extra_flags & CloneFlag.PIDFD:
            args.pidfd = ctypes.addressof(pidfd_cell)
        pid = Sys.clone3(args)
        return pid, int(pidfd_cell.value)

    def run(
        self,
        fn: Callable[[], int | None],
        extra_flags: CloneFlag = CloneFlag.NONE,
    ) -> int:
        pid, _ = self.clone_into(extra_flags=extra_flags)
        if pid == 0:
            try:
                self.close()
                rc = fn()
                os._exit(0 if rc is None else int(rc))
            except BaseException:
                os._exit(126)
        return pid

    def make_mount(
        self,
        fstype: str,
        attr_flags: MountAttrFlag = MountAttrFlag.NONE,
        options: Mapping[str, str | None] | None = None,
    ) -> int:
        fsfd = Sys.fsopen(fstype)
        try:
            Sys.fsconfig(fsfd, FsconfigCmd.SET_USERLAND, aux=self.fd)
            if options:
                for k, v in options.items():
                    if v is None:
                        Sys.fsconfig(fsfd, FsconfigCmd.SET_FLAG, key=k)
                    else:
                        Sys.fsconfig(
                            fsfd, FsconfigCmd.SET_STRING, key=k, value=str(v)
                        )
            Sys.fsconfig(fsfd, FsconfigCmd.CMD_CREATE)
            return Sys.fsmount(fsfd, attr_flags=attr_flags)
        finally:
            os.close(fsfd)


@dataclass
class Cell:
    name: str
    flags: UserlandFlag = UserlandFlag.DEFAULT
    rns: Userland = field(init=False)
    mntns_fd: int = field(init=False, default=-1)
    root_dfd: int = field(init=False, default=-1)

    def __post_init__(self) -> None:
        self.rns = Userland(self.flags)
        try:
            self.mntns_fd = self.rns.get_nsfd(CloneFlag.NEWNS)
        except Exception:
            self.rns.close()
            raise

    def __enter__(self) -> Cell:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    @staticmethod
    def _close_fd(fd: int) -> int:
        if fd >= 0:
            with suppress(OSError):
                os.close(fd)
        return -1

    def _move_to_mntns(self, mfd: int, target: str) -> None:
        Sys.move_mount(
            mfd,
            "",
            self.mntns_fd,
            target,
            MoveMountFlag.F_EMPTY_PATH | MoveMountFlag.T_MNTNS,
        )

    def _consume_mount(self, mfd: int, target: str) -> None:
        try:
            self._move_to_mntns(mfd, target.lstrip("/"))
        finally:
            os.close(mfd)

    def setup_rootfs(
        self,
        dirs: Sequence[str] = ("proc", "tmp", "mnt"),
        mount_procfs: bool = True,
        host_runtime: bool = False,
        map_ugid: bool = True,
    ) -> None:
        if map_ugid:
            self.rns.map_self_ugid()
        rootfd = self.rns.make_mount("tmpfs")
        bind_dirs: list[str] = []
        try:
            for d in dirs:
                os.mkdir(d, 0o755, dir_fd=rootfd)
            if host_runtime:
                for entry in HOST_RUNTIME_ENTRIES:
                    host_path = f"/{entry}"
                    if os.path.islink(host_path):
                        os.symlink(
                            os.readlink(host_path), entry, dir_fd=rootfd
                        )
                    elif os.path.isdir(host_path):
                        os.mkdir(entry, 0o755, dir_fd=rootfd)
                        bind_dirs.append(entry)
            self._move_to_mntns(rootfd, "/")
        except Exception:
            os.close(rootfd)
            raise
        self.root_dfd = rootfd
        for entry in bind_dirs:
            self.bind_mount(f"/{entry}", entry)
        if mount_procfs and "proc" in dirs:
            self.mount_fs("proc", "proc")

    def mount_fs(
        self,
        fstype: str,
        target: str,
        attr_flags: MountAttrFlag = MountAttrFlag.NONE,
        options: Mapping[str, str | None] | None = None,
    ) -> None:
        mfd = self.rns.make_mount(
            fstype, attr_flags=attr_flags, options=options
        )
        self._consume_mount(mfd, target)

    def bind_mount(self, host_src: str, target: str) -> None:
        Sys.move_mount(
            Sys.AT_FDCWD,
            host_src,
            self.mntns_fd,
            target.lstrip("/"),
            MoveMountFlag.T_MNTNS | MoveMountFlag.CLONE,
        )

    def spawn(
        self,
        argv: Sequence[str],
        env: Mapping[str, str] | None = None,
        resolve_in_root: bool = True,
    ) -> int:
        bin_fd = -1
        if resolve_in_root and self.root_dfd >= 0:
            bin_fd = Sys.openat2(
                self.root_dfd,
                argv[0],
                os.O_RDONLY | os.O_CLOEXEC,
                resolve=ResolveFlag.IN_ROOT,
            )
        try:
            pid, _ = self.rns.clone_into(
                extra_flags=CloneFlag.AUTOREAP, exit_signal=0
            )
            if pid == 0:
                try:
                    self.close()
                    if bin_fd >= 0:
                        Sys.execveat(bin_fd, "", argv, env, AtFlag.EMPTY_PATH)
                    if env is None:
                        os.execv(argv[0], list(argv))
                    else:
                        os.execve(argv[0], list(argv), dict(env))
                except BaseException:
                    os._exit(127)
            return pid
        finally:
            self._close_fd(bin_fd)

    def kill(self, sig: signal.Signals | int = signal.SIGTERM) -> None:
        self.rns.kill(sig)

    def wait(self, nohang: bool = False) -> WaitResult:
        return self.rns.wait(os.WNOHANG if nohang else 0)

    def close(self) -> None:
        self.root_dfd = self._close_fd(self.root_dfd)
        self.mntns_fd = self._close_fd(self.mntns_fd)
        self.rns.close()
