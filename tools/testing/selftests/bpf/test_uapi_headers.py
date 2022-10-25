#!/usr/bin/env python3
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

# A script to test header guards in vmlinux.h by compiling a simple C
# snippet for a set of selected UAPI headers. The snippet being
# compiled looks as follows:
#
#   #include <some_uapi_header.h>
#   #include "vmlinux.h"
#
#   __attribute__((section("tc"), used))
#   int syncookie_tc(struct __sk_buff *skb) { return 0; }
#
# If header guards are placed correctly in vmlinux.h the snippet
# should compile w/o errors.
#
# The script could be used in two modes:
# - interactive BPF testing and CI;
# - debug mode.
#
# * Interactive BPF testing and CI
#
# Run script as follows:
#
#   ./test_uapi_headers.py
#
# In this mode the following actions are performed:
# - kernel headers are installed to a temporary directory;
# - a list of known good uapi headers is read from ./good_uapi_headers.txt;
# - the snippet above is compiled by clang using BPF target for each header;
# - if shell is interactive the progress / ETA are reported during execution;
# - pass / fail statistics is reported in the end;
# - headers temporary directory is deleted;
# - script exit code is 0 if snippet could be compiled for all headers.
#
# The vmlinux.h processing time is significant (~700ms using Intel i7-4710HQ),
# thus the headers are processed in parallel.
#
# * Debug mode
#
# The following parameters are available for debugging:
#
#   test_uapi_headers.py \
#            [-h] [--kheaders KHEADERS] [--vmlinuxh VMLINUXH] [--test TEST]
#
#   options:
#     -h, --help           show this help message and exit
#     --kheaders KHEADERS  path to exported kernel headers
#     --vmlinuxh VMLINUXH  path to vmlinux.h
#     --test TEST          name of the header -or-
#                          file with header names -or-
#                          special value '*'
#
# When --kheaders is specified the temporary directory is not created
# and KHEADERS is used instead. It is assumed that headers are already
# installed to KHEADERS.
#
# When TEST names a header (e.g. 'linux/tcp.h') it is the to test.
# When TEST names a file this file should contain a list of
# headers to test one per line.
# When TEST is '*' all exported headers are tested.
#
# The simplest way to debug an issue with a single header is:
#
#   ./test_uapi_headers.py --test linux/tcp.h

import subprocess
import concurrent.futures
import pathlib
import time
import os
import sys
import argparse
import tempfile
import shutil
import atexit
from dataclasses import dataclass

@dataclass
class Result:
    header: pathlib.Path
    returncode: int
    stderr: str

def run_one(header, kheaders, vmlinuxh):
    code=f'''
#include <{header}>
#include "{vmlinuxh}"

__attribute__((section("tc"), used))
int syncookie_tc(struct __sk_buff *skb)
{{
    return 0;
}}
    '''
    command = f'''
{os.getenv('CLANG', 'clang')} \
    -g -Werror -mlittle-endian \
    -D__x86_64__ \
    -Xclang -fwchar-type=short \
    -Xclang -fno-signed-wchar \
    -I{kheaders}/include/ \
    -Wno-compare-distinct-pointer-types \
    -mcpu=v3 \
    -O2 \
    -target bpf \
    -x c \
    -o /dev/null \
    -fsyntax-only \
    -
'''
    proc = subprocess.run(command, input=code, capture_output=True,
                          shell=True, encoding='utf8')
    return Result(header=header,
                  returncode=proc.returncode,
                  stderr=proc.stderr)

def run_all(headers, kheaders, vmlinuxh):
    start_time = time.time()
    ok = 0
    fail = 0
    failures = []
    remain = len(headers)
    print_progress = sys.stdout.isatty()
    print(f'Processing {remain} headers.')
    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        for result in executor.map(lambda header: run_one(header, kheaders, vmlinuxh),
                                   headers):
            if result.returncode == 0:
                print(f"{result.header:<60}   ok")
                ok += 1
            else:
                print(f"{result.header:<60} fail")
                fail += 1
                failures.append(result)
            remain -= 1
            if print_progress:
                elapsed = time.time() - start_time
                processed = ok + fail
                time_per_header = elapsed / processed
                eta = int(remain * time_per_header)
                # keep this shorter than header ok/fail line
                line = f"Ok {ok: >4} Fail {fail: >4} Remain {remain: >4} ETA {eta: >4}s"
                print(line, end="\r")
    if print_progress:
        print('')
    elapsed = int(time.time() - start_time)
    if fail == 0:
        print(f"Done in {elapsed}s, all {len(headers)} ok.")
    else:
        print('----- Failure details -----')
        for result in failures:
            print(f'{result.header}: rc = {result.returncode}')
            for line in result.stderr.split('\n'):
                print(f"{result.header}: {line}")
        print(f"Done in {elapsed}s, {fail} out of {len(headers)} failed.")
    return fail == 0

def main(argv):
    bpf_test_dir = pathlib.Path(__file__).resolve().parent
    default_vmlinuxh = bpf_test_dir / './tools/include/vmlinux.h'
    parser = argparse.ArgumentParser()
    parser.add_argument("--kheaders", type=str, help='path to exported kernel headers')
    parser.add_argument("--vmlinuxh", type=str, default=default_vmlinuxh,
                        help='path to vmlinux.h')
    parser.add_argument("--test", type=str,
                        default='./good_uapi_headers.txt',
                        help="name of the header | file with header names | special value '*'")
    args = parser.parse_args(argv)

    if args.kheaders is None:
        kheaders = tempfile.mkdtemp(prefix='kheaders')
        atexit.register(lambda: shutil.rmtree(kheaders))
        kernel_dir = bpf_test_dir / '../../../../'
        # Capture both stdout and stderr as stdout to simplify CI logging
        subprocess.run(f'make -C {kernel_dir} INSTALL_HDR_PATH={kheaders} headers_install',
                       stdout=sys.stdout, stderr=sys.stdout,
                       check=True, shell=True)
    else:
        kheaders = args.kheaders

    if os.path.exists(args.test):
        with open(args.test, 'r') as list_file:
            headers = [line.strip() for line in list_file]
    elif args.test == '*':
        headers = [p.relative_to(f'{kheaders}/include').as_posix()
                   for p in pathlib.Path(kheaders).rglob("*.h")]
    else:
        headers = [args.test]

    if run_all(headers, kheaders, args.vmlinuxh):
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == '__main__':
    main(sys.argv[1:])
