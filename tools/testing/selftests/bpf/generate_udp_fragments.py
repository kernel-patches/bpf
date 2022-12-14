#!/bin/env python3

"""
This script helps generate fragmented UDP packets.

While it is technically possible to dynamically generate
fragmented packets in C, it is much harder to read and write
said code. `scapy` is relatively industry standard and really
easy to read / write.

So we choose to write this script that generates valid C code.
"""

import argparse
from scapy.all import *

def print_frags(frags):
    for idx, frag in enumerate(frags):
        # 10 bytes per line to keep width in check
        chunks = [frag[i: i+10] for i in range(0, len(frag), 10)]
        chunks_fmted = [", ".join([str(hex(b)) for b in chunk]) for chunk in chunks]

        print(f"static uint8_t frag{idx}[] = {{")
        for chunk in chunks_fmted:
            print(f"\t{chunk},")
        print(f"}};")


def main(args):
    # srcip of 0 is filled in by IP_HDRINCL
    sip = "0.0.0.0"
    dip = args.dst_ip
    sport = args.src_port
    dport = args.dst_port
    payload = args.payload.encode()

    # Disable UDP checksums to keep code simpler
    pkt = IP(src=sip,dst=dip) / UDP(sport=sport,dport=dport,chksum=0) / Raw(load=payload)

    frags = [f.build() for f in pkt.fragment(24)]
    print_frags(frags)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("dst_ip")
    parser.add_argument("src_port", type=int)
    parser.add_argument("dst_port", type=int)
    parser.add_argument("payload")
    args = parser.parse_args()

    main(args)
