#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
"""Exchange values between host and guest BPF through NUMA-backed RAM.

Build with the BPF selftests Makefile. Helpers are found in the current
directory or beside this script, so OUTPUT builds and installed tests work.
Use --build-dir to select another helper directory and --kernel (or
ARENA_KVM_KERNEL) to select the kernel booted by virtme-ng. By default, use
the source tree's kernel when available, otherwise the running release.
"""

# Dependencies: Python 3.9+, virtme-ng, busybox-static, qemu, util-linux (script).

import argparse
import array
import ctypes
import mmap
import os
from pathlib import Path
import queue
import re
import shutil
import shlex
import signal
import socket
import struct
import subprocess
import sys
import threading
import time


PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
KSFT_SKIP = 4
HELPER_TIMEOUT = 20
GUEST_MEMORY = 512 * 1024 * 1024
# RAM starts for virtme-ng's PC/q35, virt (arm64/riscv64), and pseries
# machines. With 512 MiB of RAM, the last NUMA node follows node 0
# without crossing a machine's RAM hole. Skip other layouts.
GUEST_RAM_BASES = {
    "x86_64": 0,
    "aarch64": 0x40000000,
    "arm64": 0x40000000,
    "riscv64": 0x80000000,
    "ppc64": 0,
    "ppc64le": 0,
}
# Leave room for guest boot allocations and allocator watermarks.
# QEMU's pseries machine requires each NUMA node to be 256 MiB aligned.
SLICE_SIZE = (256 if os.uname().machine in ("ppc64", "ppc64le") else 16) \
    * 1024 * 1024
ARENA_SIZE = 2 * SLICE_SIZE
NUM_PAGES = ARENA_SIZE // PAGE_SIZE
GUEST_READY = 0x4152454E414B564D
HOST_FIRST = 0x123456789ABCDEF0
GUEST_FIRST = 0xFEDCBA9876543210
HOST_SECOND = 0x1020304050607080
GUEST_SECOND = 0x8070605040302010


def progress(message):
    print(f"# arena_kvm: {message}", flush=True)


class TestSkipped(Exception):
    pass


class TestTerminated(BaseException):
    def __init__(self, signum):
        self.signum = signum


def terminate(signum, frame):
    # A second signal must not interrupt cleanup of pins and descendants.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    raise TestTerminated(signum)


def enable_subreaper():
    # Adopt orphaned descendants even when script/vng changes session.
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = (ctypes.c_int, *([ctypes.c_ulong] * 4))
    if libc.prctl(36, 1, 0, 0, 0):  # PR_SET_CHILD_SUBREAPER
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def children(pid):
    # /proc/PID/task/TID/children requires CONFIG_CHECKPOINT_RESTORE.
    # PPid is always available and covers children of every parent thread.
    result = set()
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        try:
            status = (path / "status").read_text()
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        for line in status.splitlines():
            if line.startswith("PPid:") and int(line.split()[1]) == pid:
                result.add(int(path.name))
                break
    return result


def stop_children(processes=()):
    # Kill direct children, then repeat for descendants adopted by the
    # subreaper. Sessions and process groups do not affect adoption.
    # Reaping until ECHILD verifies that the entire owned tree has exited.
    known = {process.pid: process for process in processes}
    deadline = time.monotonic() + 10
    while True:
        for pid in children(os.getpid()):
            try:
                fd = os.pidfd_open(pid)
            except ProcessLookupError:
                continue
            try:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                os.close(fd)
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return
            if not pid:
                break
            if pid in known:
                known[pid].returncode = os.waitstatus_to_exitcode(status)
        if time.monotonic() >= deadline:
            raise TimeoutError("guest descendants did not exit")
        time.sleep(0.01)


def getq(arena, offset):
    return struct.unpack_from("=Q", arena, offset)[0]


def wait_reply(runner, obj, fd, offset, guest, lines):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        result = run_host_bpf(runner, obj, fd, offset, "check_reply",
                              timeout=max(0.001, deadline - time.monotonic()))
        if result == 0:
            return
        if result != 1:
            raise RuntimeError(f"guest BPF reply is wrong: result={result}")
        if guest.poll() is not None:
            raise RuntimeError("guest exited early:\n" + "".join(lines))
        time.sleep(0.001)
    raise TimeoutError(f"timed out waiting for BPF reply at offset {offset}")


def read_lines(guest, messages, lines):
    for line in guest.stdout:
        lines.append(line)
        # Serial startup may prefix a message with NULs echoed as ^@.
        messages.put(re.sub(r"^(?:\x00|\^@)+", "", line.strip()))


def wait_message(messages, lines, expected, guest):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            line = messages.get(timeout=0.5)
        except queue.Empty:
            if guest.poll() is not None:
                break
            continue
        if expected in line:
            return line
        if "GUEST_BPF_FAILED" in line:
            break
        if "GUEST_BPF_SKIPPED" in line:
            raise TestSkipped(line)
    raise RuntimeError(f"guest did not print {expected} "
                       f"(launcher exit status: {guest.poll()}):\n" +
                       "".join(lines))


def run_host_bpf(runner, obj, fd, offset, program="exchange",
                 timeout=HELPER_TIMEOUT):
    output = subprocess.check_output(
        [str(runner), str(fd), str(obj), str(offset), program],
        pass_fds=(fd,), text=True, timeout=timeout)
    return int(output)


def resolve_vng():
    executable = shutil.which("vng")
    if not executable or not os.access(executable, os.X_OK):
        print("SKIP: virtme-ng (vng) is unavailable")
        return None, None
    return executable, os.environ.copy()


def start_guest(pin, build, kernel, index, vng, env, guests):
    node0_size = GUEST_MEMORY - SLICE_SIZE
    base = GUEST_RAM_BASES[os.uname().machine] + node0_size
    progress(f"Starting guest {index}: {SLICE_SIZE // (1024 * 1024)} MiB "
             f"slice at file offset {index * SLICE_SIZE:#x}, "
             f"NUMA node 1 physical base {base:#x}")
    qemu_opts = (
        f"-object memory-backend-file,id=signal,size={SLICE_SIZE},share=on,"
        f"offset={index * SLICE_SIZE},mem-path={pin} "
        "-numa node,nodeid=1,memdev=signal"
    )
    guest_command = [str(build / "arena_kvm_guest-init"),
                     str(build / "arena_kvm_guest.bpf.o")]
    command = [
        vng, "--verbose", "--run", str(kernel), "--cpus", "2",
        "--memory", f"{GUEST_MEMORY // (1024 * 1024)}M",
        "--numa", str(node0_size),
        "--exec",
        shlex.join(guest_command),
        "--append", f"arena_kvm.base={base:#x} arena_kvm.size={SLICE_SIZE}",
        f"--qemu-opts={qemu_opts}",
    ]
    lines = []
    messages = queue.Queue()
    guest = subprocess.Popen(["script", "-e", "-q", "-c", shlex.join(command),
                              "/dev/null"], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, env=env,
                             start_new_session=True)
    # Register ownership before thread construction or startup can fail.
    guests.append((guest, messages, lines, None))
    reader = threading.Thread(target=read_lines, args=(guest, messages, lines),
                              daemon=True)
    guests[-1] = guest, messages, lines, reader
    reader.start()


def stop_guests(guests):
    stop_children(process for process, _, _, _ in guests)
    for process, _, _, reader in guests:
        process.wait(timeout=10)
        if reader is not None and reader.ident is not None:
            reader.join(timeout=2)
            if reader.is_alive():
                raise RuntimeError("guest output reader did not exit")
        process.stdout.close()


def exchange(pin, fd, arena, build, kernel, vng, env):
    guests = []
    try:
        for index in range(2):
            start_guest(pin, build, kernel, index, vng, env, guests)
        offsets = []
        for index, (process, messages, lines, _) in enumerate(guests):
            progress(f"Waiting for guest {index} to allocate its BPF arena page "
                     "and check that BPF cannot free it")
            ready = wait_message(messages, lines, "GUEST_BPF_READY", process)
            match = re.fullmatch(r"GUEST_BPF_READY (\d+) (\d+)", ready)
            if not match:
                raise RuntimeError(f"malformed guest page offset: {ready}")
            relative = int(match.group(1))
            if int(match.group(2)) != PAGE_SIZE:
                raise RuntimeError("host and guest page sizes differ")
            offset = index * SLICE_SIZE + relative
            if relative >= SLICE_SIZE or relative % PAGE_SIZE or \
                    getq(arena, offset) != GUEST_READY:
                raise RuntimeError(f"invalid guest {index} page offset {relative}")
            offsets.append(offset)
            progress(f"Guest {index} ready: page offset {relative:#x} in slice, "
                     f"{offset:#x} in host arena")
        # The QEMU VMA and the open map FD retain the arena after unlink.
        progress("Unpinning the host arena while both guests retain mappings")
        os.unlink(pin)
        runner = build / "arena_kvm_host-runner"
        obj = build / "arena_kvm_host.bpf.o"
        for offset in offsets:
            if run_host_bpf(runner, obj, fd, offset, "probe_free") != 0 or \
                    getq(arena, offset) != GUEST_READY:
                raise RuntimeError("host BPF freed a shared RAM page")
        progress("Host BPF page-free checks passed for both shared pages")

        for index, offset in enumerate(offsets):
            progress(f"Round 1: host -> guest {index}, value {HOST_FIRST:#018x}")
            result = run_host_bpf(runner, obj, fd, offset)
            if result != 0:
                raise RuntimeError(f"guest {index} first result={result}")
            other = offsets[1 - index]
            if index == 0 and getq(arena, other + 16) != 0:
                raise RuntimeError("guest 0 write modified guest 1 signal")
            if index == 0:
                progress("Guest 1 signal unchanged after host write to guest 0")

        for index, (process, messages, lines, _) in enumerate(guests):
            offset = offsets[index]
            wait_reply(runner, obj, fd, offset, process, lines)
            progress(f"Round 1: guest {index} -> host, "
                     f"verified value {GUEST_FIRST:#018x}")

        # Guest 0 exits while guest 1 keeps its slice mapped and active.
        for index, (process, messages, lines, _) in enumerate(guests):
            offset = offsets[index]
            progress(f"Round 2: host -> guest {index}, value {HOST_SECOND:#018x}")
            if run_host_bpf(runner, obj, fd, offset) != 0:
                raise RuntimeError(f"host BPF failed guest {index} second value")
            wait_reply(runner, obj, fd, offset, process, lines)
            progress(f"Round 2: guest {index} -> host, "
                     f"verified value {GUEST_SECOND:#018x}")
            if run_host_bpf(runner, obj, fd, offset) != 2:
                raise RuntimeError(f"host BPF failed guest {index} reply")
            wait_message(messages, lines, "GUEST_BPF_EXCHANGED", process)
            process.wait(timeout=15)
            if process.returncode:
                raise RuntimeError(f"guest {index} failed:\n" + "".join(lines))
            progress(f"Guest {index} completed and exited successfully")
            if index == 0:
                progress("Continuing with guest 1 after guest 0 exits")
        print(f"OK: two guests exchanged BPF values through arena slices {offsets}")
    finally:
        progress("Cleaning up guest processes")
        stop_guests(guests)


def skip(reason):
    print(f"SKIP: {reason}")
    return KSFT_SKIP


def create_arena(pin, build):
    parent, child = socket.socketpair()
    with parent, child:
        result = subprocess.run(
            [str(build / "arena_kvm_host-runner"), "--create", pin,
             str(child.fileno()), str(NUM_PAGES)], pass_fds=(child.fileno(),),
            timeout=HELPER_TIMEOUT)
        child.close()
        if result.returncode == KSFT_SKIP:
            return None
        result.check_returncode()
        fds = array.array("i")
        _, ancillary, flags, _ = parent.recvmsg(
            1, socket.CMSG_SPACE(fds.itemsize))
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                fds.frombytes(data[:len(data) - len(data) % fds.itemsize])
        if flags & socket.MSG_CTRUNC or len(fds) != 1:
            for fd in fds:
                os.close(fd)
            raise RuntimeError("host helper did not send one arena FD")
        return fds[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path,
                        help="directory containing the built helpers")
    parser.add_argument("--kernel", default=os.environ.get("ARENA_KVM_KERNEL"),
                        help="virtme-ng kernel path or release (default: source "
                             "tree kernel, otherwise running kernel)")
    args = parser.parse_args()
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        return skip("Python 3.9+ with Linux pidfd support is required")
    machine = os.uname().machine
    if machine not in GUEST_RAM_BASES:
        return skip(f"unknown guest RAM layout for architecture {machine}")
    if struct.calcsize("P") != 8:
        return skip("BPF arenas require a supported 64-bit architecture")
    if os.geteuid() != 0:
        return skip("this test requires root")
    if SLICE_SIZE % PAGE_SIZE:
        return skip("arena slices must contain a whole number of pages")
    if not os.path.ismount("/sys/fs/bpf"):
        return skip("mount bpffs first")
    directory = Path(__file__).resolve().parent
    build = args.build_dir
    if build is None:
        build = Path.cwd() if (Path.cwd() / "arena_kvm_host-runner").is_file() \
            else directory
    build = build.resolve()
    kernel = args.kernel
    if kernel is None:
        kernel = next((str(p) for p in directory.parents
                       if (p / "vmlinux").is_file()), os.uname().release)
    vng, env = resolve_vng()
    if not vng:
        return KSFT_SKIP
    qemu_arch = {"arm64": "aarch64", "ppc64le": "ppc64"}.get(machine, machine)
    for tool in ("script", f"qemu-system-{qemu_arch}"):
        if not shutil.which(tool, path=env.get("PATH")):
            return skip(f"{tool} is unavailable")
    for name in ("arena_kvm_guest-init", "arena_kvm_guest.bpf.o",
                 "arena_kvm_host-runner", "arena_kvm_host.bpf.o"):
        if not (build / name).exists():
            return skip(f"missing {build / name}; build the BPF selftests")
    for name in ("arena_kvm_host.bpf.o", "arena_kvm_guest.bpf.o"):
        result = subprocess.run([str(build / "arena_kvm_host-runner"),
                                 "--check-bpf", str(build / name)],
                                timeout=HELPER_TIMEOUT)
        if result.returncode == KSFT_SKIP:
            return skip("BPF compiler lacks arena address-space conversions")
        result.check_returncode()
    if subprocess.run([str(build / "arena_kvm_host-runner"),
                       "--check-kvm"], timeout=HELPER_TIMEOUT).returncode:
        return skip("KVM is unavailable or its API version is unsupported")
    pin = f"/sys/fs/bpf/arena_kvm_{os.getpid()}"
    progress(f"Architecture: {machine}; "
             f"page size: {PAGE_SIZE} bytes")
    progress(f"Creating and pinning a {ARENA_SIZE // (1024 * 1024)} MiB "
             f"host arena at {pin}")
    try:
        fd = create_arena(pin, build)
        if fd is None:
            return skip("pinned BPF arenas are unsupported")
        try:
            if os.stat(pin).st_size != ARENA_SIZE:
                raise RuntimeError("pinned arena has the wrong size")
            with mmap.mmap(fd, ARENA_SIZE, flags=mmap.MAP_SHARED,
                           prot=mmap.PROT_READ | mmap.PROT_WRITE) as arena:
                progress(f"Populating {NUM_PAGES} host arena pages before "
                         "starting the guests")
                # Populate the file pages before QEMU uses them as RAM.
                for i in range(NUM_PAGES):
                    arena[i * PAGE_SIZE]
                exchange(pin, fd, arena, build, kernel, vng, env)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(pin):
            os.unlink(pin)


if __name__ == "__main__":
    enable_subreaper()
    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    try:
        status = main()
    except TestSkipped as err:
        status = skip(str(err))
    except TestTerminated as err:
        progress(f"Terminated by signal {err.signum}")
        status = 128 + err.signum
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        stop_children()
    sys.exit(status)
