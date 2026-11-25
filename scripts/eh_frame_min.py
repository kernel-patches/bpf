#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only OR MIT
"""
Offline ELF .eh_frame / Minimal DWARF CFA coverage and size analyzer.

Note: This script is a standalone developer/benchmarking inspection tool and
is NOT invoked during Kbuild (which uses the standalone C host tool in
scripts/min_eh_frame.c when CONFIG_UNWINDER_DWARF_CFI_MINIFY=y).

It parses ELF32/ELF64 relocatable objects (.o, .ko), vmlinux images, user
executables, and shared libraries across x86_64, i386, arm64, arm, and riscv,
reporting:
  - .text, .eh_frame, .eh_frame_hdr, .sframe, and .orc_unwind section sizes
  - Simulated minified .eh_frame + .eh_frame_hdr sizes and byte savings
  - Minimal DWARF CFA FDE coverage (supported vs. unsupported FDEs & reasons)
  - Kept FP/RA register rules vs. ignored general-purpose register spill ops
  - Maximum DW_CFA_remember_state nesting depth and top DWARF CFA opcodes

Example usage (from the kernel tree root, invoke via ./scripts/eh_frame_min*):
  1. Analyze a built vmlinux image (with or without build-time minification):
       $ eh_frame_min.py vmlinux

  2. Compare multiple kernel objects, loadable modules, or cross-arch builds:
       $ eh_frame_min.py mm/vmscan.o kernel/fork.o fs/ext4/inode.o
       $ eh_frame_min.py build_arm64/vmlinux build_riscv/vmlinux

  3. Analyze existing user-space binaries and shared libraries:
       $ eh_frame_min.py /bin/bash /lib/x86_64-linux-gnu/libc.so.6

  4. Emit a standalone minified .eh_frame section blob for differential tests:
       $ eh_frame_min.py --minify /tmp/eh_frame.min mm/vmscan.o

Example output:
  === build_arm64/vmlinux (arm64) ===
    .text size              : 18,500,228 B
    Original .eh_frame      :  2,294,092 B  (1 CIEs, 69,765 FDEs)
    Original .eh_frame_hdr  :    558,132 B  (combined: 2,852,224 B)
    Minified .eh_frame      :  2,285,920 B  (1 CIEs, -0.4% vs .eh_frame)
    Minified + .eh_frame_hdr:  2,844,052 B  (-0.3% combined)
    FDE bytecode payload    :  1,108,067 B -> 953,348 B (avg 13.7 B/FDE)
    .sframe section         :  2,938,460 B
    Minimal DWARF coverage  : 69,765 / 69,765 FDEs (100.00%)
    Register ops kept/skip  : 125,630 kept (FP/RA), 0 ignored (other GPRs/args)
    Max remember_state depth: 1
"""

import argparse
import os
import struct
import sys
from collections import Counter

# DWARF register numbers per ELF e_machine (drap = transient stack-realign scratch regs)
ARCH_REGS = {
    62: {"name": "x86_64", "sp": 7, "fp": 6, "ra": 16, "drap": {1, 2, 5, 10, 13}},  # EM_X86_64
    3:  {"name": "i386",   "sp": 4, "fp": 5, "ra": 8,  "drap": {1, 7}},              # EM_386 (%ecx, %edi)
    40: {"name": "arm",    "sp": 13, "fp": 11, "ra": 14, "drap": set()},             # EM_ARM
    183: {"name": "arm64", "sp": 31, "fp": 29, "ra": 30, "drap": set()},             # EM_AARCH64
    243: {"name": "riscv", "sp": 2, "fp": 8, "ra": 1, "drap": set()},                # EM_RISCV
}

DW_CFA_nop                          = 0x00
DW_CFA_set_loc                      = 0x01
DW_CFA_advance_loc1                 = 0x02
DW_CFA_advance_loc2                 = 0x03
DW_CFA_advance_loc4                 = 0x04
DW_CFA_offset_extended              = 0x05
DW_CFA_restore_extended             = 0x06
DW_CFA_undefined                    = 0x07
DW_CFA_same_value                   = 0x08
DW_CFA_register                     = 0x09
DW_CFA_remember_state               = 0x0a
DW_CFA_restore_state                = 0x0b
DW_CFA_def_cfa                      = 0x0c
DW_CFA_def_cfa_register             = 0x0d
DW_CFA_def_cfa_offset               = 0x0e
DW_CFA_def_cfa_expression           = 0x0f
DW_CFA_expression                   = 0x10
DW_CFA_offset_extended_sf           = 0x11
DW_CFA_def_cfa_sf                   = 0x12
DW_CFA_def_cfa_offset_sf            = 0x13
DW_CFA_val_offset                   = 0x14
DW_CFA_val_offset_sf                = 0x15
DW_CFA_val_expression               = 0x16
DW_CFA_AARCH64_negate_ra_state      = 0x2d
DW_CFA_GNU_args_size                = 0x2e
DW_CFA_GNU_negative_offset_extended = 0x2f

OPCODE_NAMES = {
    0x00: "DW_CFA_nop",
    0x01: "DW_CFA_set_loc",
    0x02: "DW_CFA_advance_loc1",
    0x03: "DW_CFA_advance_loc2",
    0x04: "DW_CFA_advance_loc4",
    0x05: "DW_CFA_offset_extended",
    0x06: "DW_CFA_restore_extended",
    0x07: "DW_CFA_undefined",
    0x08: "DW_CFA_same_value",
    0x09: "DW_CFA_register",
    0x0a: "DW_CFA_remember_state",
    0x0b: "DW_CFA_restore_state",
    0x0c: "DW_CFA_def_cfa",
    0x0d: "DW_CFA_def_cfa_register",
    0x0e: "DW_CFA_def_cfa_offset",
    0x0f: "DW_CFA_def_cfa_expression",
    0x10: "DW_CFA_expression",
    0x11: "DW_CFA_offset_extended_sf",
    0x12: "DW_CFA_def_cfa_sf",
    0x13: "DW_CFA_def_cfa_offset_sf",
    0x14: "DW_CFA_val_offset",
    0x15: "DW_CFA_val_offset_sf",
    0x16: "DW_CFA_val_expression",
    0x2d: "DW_CFA_negate_ra_state/window_save",
    0x2e: "DW_CFA_GNU_args_size",
    0x2f: "DW_CFA_GNU_negative_offset_extended",
}

DW_EH_PE_omit     = 0xff
DW_EH_PE_absptr   = 0x00
DW_EH_PE_uleb128  = 0x01
DW_EH_PE_udata2   = 0x02
DW_EH_PE_udata4   = 0x03
DW_EH_PE_udata8   = 0x04
DW_EH_PE_sleb128  = 0x09
DW_EH_PE_sdata2   = 0x0a
DW_EH_PE_sdata4   = 0x0b
DW_EH_PE_sdata8   = 0x0c
DW_EH_PE_pcrel    = 0x10
DW_EH_PE_indirect = 0x80


def read_uleb128(buf, pos, end):
    val = 0
    shift = 0
    while pos < end:
        b = buf[pos]
        pos += 1
        val |= (b & 0x7f) << shift
        if not (b & 0x80):
            return val, pos
        shift += 7
        if shift > 63:
            raise ValueError("ULEB128 overflow")
    raise ValueError("Truncated ULEB128")


def read_sleb128(buf, pos, end):
    val = 0
    shift = 0
    while pos < end:
        b = buf[pos]
        pos += 1
        val |= (b & 0x7f) << shift
        shift += 7
        if not (b & 0x80):
            if b & 0x40:
                val |= -(1 << shift)
            return val, pos
        if shift > 63:
            raise ValueError("SLEB128 overflow")
    raise ValueError("Truncated SLEB128")


def encode_uleb128(val):
    if val < 0:
        raise ValueError("Negative ULEB128")
    out = bytearray()
    while True:
        b = val & 0x7f
        val >>= 7
        if val:
            b |= 0x80
        out.append(b)
        if not val:
            break
    return bytes(out)


def encode_sleb128(val):
    out = bytearray()
    more = True
    while more:
        b = val & 0x7f
        val >>= 7
        if (val == 0 and not (b & 0x40)) or (val == -1 and (b & 0x40)):
            more = False
        else:
            b |= 0x80
        out.append(b)
    return bytes(out)


def encoded_ptr_size(enc, addr_size):
    if enc == DW_EH_PE_omit:
        return 0
    fmt = enc & 0x0f
    if fmt == DW_EH_PE_absptr:
        return addr_size
    if fmt in (DW_EH_PE_udata2, DW_EH_PE_sdata2):
        return 2
    if fmt in (DW_EH_PE_udata4, DW_EH_PE_sdata4):
        return 4
    if fmt in (DW_EH_PE_udata8, DW_EH_PE_sdata8):
        return 8
    return None


def read_encoded_ptr(buf, pos, end, enc, addr_size, sec_vaddr):
    if enc == DW_EH_PE_omit:
        return 0, pos
    orig_pos = pos
    fmt = enc & 0x0f
    if fmt == DW_EH_PE_absptr:
        fmt_str = "<Q" if addr_size == 8 else "<I"
        val = struct.unpack_from(fmt_str, buf, pos)[0]
        pos += addr_size
    elif fmt == DW_EH_PE_udata2:
        val = struct.unpack_from("<H", buf, pos)[0]
        pos += 2
    elif fmt == DW_EH_PE_sdata2:
        val = struct.unpack_from("<h", buf, pos)[0]
        pos += 2
    elif fmt == DW_EH_PE_udata4:
        val = struct.unpack_from("<I", buf, pos)[0]
        pos += 4
    elif fmt == DW_EH_PE_sdata4:
        val = struct.unpack_from("<i", buf, pos)[0]
        pos += 4
    elif fmt == DW_EH_PE_udata8:
        val = struct.unpack_from("<Q", buf, pos)[0]
        pos += 8
    elif fmt == DW_EH_PE_sdata8:
        val = struct.unpack_from("<q", buf, pos)[0]
        pos += 8
    elif fmt == DW_EH_PE_uleb128:
        val, pos = read_uleb128(buf, pos, end)
    elif fmt == DW_EH_PE_sleb128:
        val, pos = read_sleb128(buf, pos, end)
    else:
        raise ValueError(f"Unsupported pointer format 0x{enc:02x}")

    adj = enc & 0x70
    if adj == DW_EH_PE_pcrel:
        val = (sec_vaddr + orig_pos + val) & ((1 << (addr_size * 8)) - 1)
    elif adj != 0x00:
        raise ValueError(f"Unsupported pointer adjustment 0x{enc:02x}")
    return val, pos


def parse_elf_sections(data):
    if data[:4] != b"\x7fELF":
        raise ValueError("Not an ELF file")
    ei_class = data[4]
    ei_data = data[5]
    if ei_data != 1:
        raise ValueError("Only little-endian ELF supported")
    if ei_class == 2:
        addr_size = 8
        _, e_machine, _, _, _, e_shoff, _, _, _, _, e_shentsize, e_shnum, e_shstrndx = (
            struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
        )
        sh_fmt = "<IIQQQQIIQQ"
    elif ei_class == 1:
        addr_size = 4
        _, e_machine, _, _, _, e_shoff, _, _, _, _, e_shentsize, e_shnum, e_shstrndx = (
            struct.unpack_from("<HHIIIIIHHHHHH", data, 16)
        )
        sh_fmt = "<IIIIIIIIII"
    else:
        raise ValueError(f"Unknown ELF class {ei_class}")

    sections = {}
    if e_shoff == 0:
        raise ValueError("ELF has no section headers")

    if e_shnum == 0 or e_shstrndx == 0xffff:
        sh0 = struct.unpack_from(sh_fmt, data, e_shoff)
        if e_shnum == 0:
            e_shnum = sh0[5]
        if e_shstrndx == 0xffff:
            e_shstrndx = sh0[6]

    if e_shnum == 0 or e_shstrndx >= e_shnum:
        raise ValueError("ELF has invalid section header counts")

    shdrs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        shdrs.append(struct.unpack_from(sh_fmt, data, off))

    shstr_off = shdrs[e_shstrndx][4]
    shstr_sz = shdrs[e_shstrndx][5]
    shstrtab = data[shstr_off : shstr_off + shstr_sz]

    for sh in shdrs:
        sh_name_idx = sh[0]
        sh_type = sh[1]
        sh_addr = sh[3]
        sh_offset = sh[4]
        sh_size = sh[5]
        end_idx = shstrtab.find(b"\x00", sh_name_idx)
        name = shstrtab[sh_name_idx:end_idx].decode("utf-8", errors="replace")
        # SHT_NOBITS == 8
        sec_bytes = b"" if sh_type == 8 else data[sh_offset : sh_offset + sh_size]
        if name in sections:
            # Accumulate sizes for multi-section objects (e.g. .text.*)
            prev_addr, prev_sz, prev_b = sections[name]
            sections[name] = (prev_addr, prev_sz + sh_size, prev_b)
        else:
            sections[name] = (sh_addr, sh_size, sec_bytes)

    return e_machine, addr_size, sections


def parse_cie(buf, entry_off, body_off, entry_end, addr_size, sec_vaddr):
    pos = body_off
    version = buf[pos]
    pos += 1
    nul = buf.find(b"\x00", pos, entry_end)
    if nul < 0:
        raise ValueError("Unterminated CIE augmentation string")
    aug = buf[pos:nul].decode("ascii", errors="replace")
    pos = nul + 1

    if version == 4:
        addr_size = buf[pos]
        seg_size = buf[pos + 1]
        pos += 2
        if seg_size != 0:
            raise ValueError("Non-zero segment selector size")

    code_align, pos = read_uleb128(buf, pos, entry_end)
    data_align, pos = read_sleb128(buf, pos, entry_end)
    if version == 1:
        ra_reg = buf[pos]
        pos += 1
    else:
        ra_reg, pos = read_uleb128(buf, pos, entry_end)

    fde_enc = DW_EH_PE_absptr
    lsda_enc = DW_EH_PE_omit
    has_z = False
    is_signal = False

    if aug.startswith("z"):
        has_z = True
        aug_len, pos = read_uleb128(buf, pos, entry_end)
        aug_end = pos + aug_len
        ap = pos
        for ch in aug[1:]:
            if ch == "L":
                lsda_enc = buf[ap]
                ap += 1
            elif ch == "P":
                p_enc = buf[ap]
                ap += 1
                _, ap = read_encoded_ptr(buf, ap, aug_end, p_enc & ~DW_EH_PE_indirect, addr_size, sec_vaddr)
            elif ch == "R":
                fde_enc = buf[ap]
                ap += 1
            elif ch == "S":
                is_signal = True
            elif ch == "B":
                # BTI / PAC key on arm64
                pass
            else:
                raise ValueError(f"Unknown CIE augmentation '{ch}' in '{aug}'")
        pos = aug_end
    elif aug != "":
        raise ValueError(f"Unsupported non-z CIE augmentation '{aug}'")

    return {
        "offset": entry_off,
        "version": version,
        "aug": aug,
        "addr_size": addr_size,
        "code_align": code_align,
        "data_align": data_align,
        "ra_reg": ra_reg,
        "fde_enc": fde_enc,
        "lsda_enc": lsda_enc,
        "has_z": has_z,
        "is_signal": is_signal,
        "has_indirect_fde": bool(fde_enc & DW_EH_PE_indirect),
        "insns": bytes(buf[pos:entry_end]),
    }


def decode_and_minify_insns(insns, cie, arch, init_row=None, is_cie=False):
    """
    Decode CFI instructions, validate against Minimal DWARF subset, and emit
    minified instructions keeping only PC advances and {CFA(SP|FP), SP, FP, RA}.
    """
    sp_reg = arch["sp"]
    fp_reg = arch["fp"]
    ra_reg = cie["ra_reg"]
    tracked_regs = {sp_reg, fp_reg, ra_reg}

    def reg_key(reg):
        if reg == fp_reg:
            return "fp"
        if reg == ra_reg:
            return "ra"
        return "sp"

    pos = 0
    end = len(insns)
    op_counts = Counter()
    ignored_reg_ops = 0
    kept_reg_ops = 0
    max_state_depth = 0
    reasons = []

    if init_row is None:
        row = {
            "cfa_reg": None,
            "cfa_off": 0,
            "sp": ("same", 0),
            "fp": ("same", 0),
            "ra": ("same", 0),
            "ra_signed": False,
        }
    else:
        row = dict(init_row)

    cie_base_row = dict(row)
    state_stack = []

    # Stream of abstract events: ("adv", delta_units) or ("op", raw_bytes)
    events = []
    pending_adv = 0

    def emit_op(raw_bytes):
        nonlocal pending_adv
        if pending_adv > 0 and not is_cie:
            events.append(("adv", pending_adv))
            pending_adv = 0
        events.append(("op", raw_bytes))

    try:
        while pos < end:
            op = insns[pos]
            pos += 1
            hi = op & 0xc0
            lo = op & 0x3f

            if hi == 0x40:
                op_counts["DW_CFA_advance_loc"] += 1
                pending_adv += lo
                continue
            if hi == 0x80:
                op_counts["DW_CFA_offset"] += 1
                reg = lo
                uoff, pos = read_uleb128(insns, pos, end)
                off = uoff * cie["data_align"]
                if reg in tracked_regs:
                    kept_reg_ops += 1
                    key = reg_key(reg)
                    if row[key] != ("off", off):
                        row[key] = ("off", off)
                        emit_op(bytes([0x80 | reg]) + encode_uleb128(uoff))
                else:
                    ignored_reg_ops += 1
                continue
            if hi == 0xc0:
                op_counts["DW_CFA_restore"] += 1
                reg = lo
                if reg in tracked_regs:
                    kept_reg_ops += 1
                    key = reg_key(reg)
                    if row[key] != cie_base_row[key]:
                        row[key] = cie_base_row[key]
                        emit_op(bytes([0xc0 | reg]))
                else:
                    ignored_reg_ops += 1
                continue

            name = OPCODE_NAMES.get(op, f"DW_CFA_unknown_0x{op:02x}")
            op_counts[name] += 1

            if op == DW_CFA_nop:
                continue
            elif op == DW_CFA_advance_loc1:
                if pos + 1 > end:
                    raise ValueError("Truncated advance_loc1")
                pending_adv += insns[pos]
                pos += 1
            elif op == DW_CFA_advance_loc2:
                pending_adv += struct.unpack_from("<H", insns, pos)[0]
                pos += 2
            elif op == DW_CFA_advance_loc4:
                pending_adv += struct.unpack_from("<I", insns, pos)[0]
                pos += 4
            elif op == DW_CFA_def_cfa:
                reg, pos = read_uleb128(insns, pos, end)
                uoff, pos = read_uleb128(insns, pos, end)
                if reg not in (sp_reg, fp_reg) and reg not in arch["drap"]:
                    reasons.append(f"def_cfa non-SP/FP reg={reg}")
                if row["cfa_reg"] != reg or row["cfa_off"] != uoff:
                    row["cfa_reg"] = reg
                    row["cfa_off"] = uoff
                    emit_op(bytes([DW_CFA_def_cfa]) + encode_uleb128(reg) + encode_uleb128(uoff))
            elif op == DW_CFA_def_cfa_sf:
                reg, pos = read_uleb128(insns, pos, end)
                soff, pos = read_sleb128(insns, pos, end)
                off = soff * cie["data_align"]
                if reg not in (sp_reg, fp_reg) and reg not in arch["drap"]:
                    reasons.append(f"def_cfa_sf non-SP/FP reg={reg}")
                if row["cfa_reg"] != reg or row["cfa_off"] != off:
                    row["cfa_reg"] = reg
                    row["cfa_off"] = off
                    emit_op(bytes([DW_CFA_def_cfa_sf]) + encode_uleb128(reg) + encode_sleb128(soff))
            elif op == DW_CFA_def_cfa_register:
                reg, pos = read_uleb128(insns, pos, end)
                if not isinstance(row["cfa_reg"], int):
                    reasons.append("def_cfa_register without reg+off CFA")
                if reg not in (sp_reg, fp_reg) and reg not in arch["drap"]:
                    reasons.append(f"def_cfa_register non-SP/FP reg={reg}")
                if row["cfa_reg"] != reg:
                    row["cfa_reg"] = reg
                    emit_op(bytes([DW_CFA_def_cfa_register]) + encode_uleb128(reg))
            elif op == DW_CFA_def_cfa_offset:
                uoff, pos = read_uleb128(insns, pos, end)
                if not isinstance(row["cfa_reg"], int):
                    reasons.append("def_cfa_offset without reg+off CFA")
                if row["cfa_off"] != uoff:
                    row["cfa_off"] = uoff
                    emit_op(bytes([DW_CFA_def_cfa_offset]) + encode_uleb128(uoff))
            elif op == DW_CFA_def_cfa_offset_sf:
                soff, pos = read_sleb128(insns, pos, end)
                off = soff * cie["data_align"]
                if not isinstance(row["cfa_reg"], int):
                    reasons.append("def_cfa_offset_sf without reg+off CFA")
                if row["cfa_off"] != off:
                    row["cfa_off"] = off
                    emit_op(bytes([DW_CFA_def_cfa_offset_sf]) + encode_sleb128(soff))
            elif op == DW_CFA_offset_extended:
                reg, pos = read_uleb128(insns, pos, end)
                uoff, pos = read_uleb128(insns, pos, end)
                off = uoff * cie["data_align"]
                if reg in tracked_regs:
                    kept_reg_ops += 1
                    key = reg_key(reg)
                    if row[key] != ("off", off):
                        row[key] = ("off", off)
                        raw = (bytes([0x80 | reg]) + encode_uleb128(uoff) if reg < 64
                               else bytes([DW_CFA_offset_extended]) + encode_uleb128(reg) + encode_uleb128(uoff))
                        emit_op(raw)
                else:
                    ignored_reg_ops += 1
            elif op == DW_CFA_offset_extended_sf:
                reg, pos = read_uleb128(insns, pos, end)
                soff, pos = read_sleb128(insns, pos, end)
                off = soff * cie["data_align"]
                if reg in tracked_regs:
                    kept_reg_ops += 1
                    key = reg_key(reg)
                    if row[key] != ("off", off):
                        row[key] = ("off", off)
                        emit_op(bytes([DW_CFA_offset_extended_sf]) + encode_uleb128(reg) + encode_sleb128(soff))
                else:
                    ignored_reg_ops += 1
            elif op == DW_CFA_GNU_negative_offset_extended:
                reg, pos = read_uleb128(insns, pos, end)
                uoff, pos = read_uleb128(insns, pos, end)
                off = -uoff * cie["data_align"]
                if reg in tracked_regs:
                    kept_reg_ops += 1
                    key = reg_key(reg)
                    if row[key] != ("off", off):
                        row[key] = ("off", off)
                        emit_op(bytes([DW_CFA_GNU_negative_offset_extended]) +
                                encode_uleb128(reg) + encode_uleb128(uoff))
                else:
                    ignored_reg_ops += 1
            elif op == DW_CFA_restore_extended:
                reg, pos = read_uleb128(insns, pos, end)
                if reg in tracked_regs:
                    kept_reg_ops += 1
                    key = reg_key(reg)
                    if row[key] != cie_base_row[key]:
                        row[key] = cie_base_row[key]
                        raw = bytes([0xc0 | reg]) if reg < 64 else bytes([DW_CFA_restore_extended]) + encode_uleb128(reg)
                        emit_op(raw)
                else:
                    ignored_reg_ops += 1
            elif op == DW_CFA_undefined:
                reg, pos = read_uleb128(insns, pos, end)
                if reg in tracked_regs:
                    kept_reg_ops += 1
                    key = reg_key(reg)
                    row[key] = ("undef", 0)
                    emit_op(bytes([DW_CFA_undefined]) + encode_uleb128(reg))
                else:
                    ignored_reg_ops += 1
            elif op == DW_CFA_same_value:
                reg, pos = read_uleb128(insns, pos, end)
                if reg in tracked_regs:
                    kept_reg_ops += 1
                    key = reg_key(reg)
                    row[key] = ("same", 0)
                    emit_op(bytes([DW_CFA_same_value]) + encode_uleb128(reg))
                else:
                    ignored_reg_ops += 1
            elif op == DW_CFA_remember_state:
                emit_op(bytes([DW_CFA_remember_state]))
                state_stack.append((dict(row), len(events) - 1))
                max_state_depth = max(max_state_depth, len(state_stack))
                if len(state_stack) > 4:
                    reasons.append(f"remember_state depth={len(state_stack)} > 4")
            elif op == DW_CFA_restore_state:
                if not state_stack:
                    reasons.append("unmatched restore_state")
                else:
                    saved_row, rem_idx = state_stack.pop()
                    if saved_row != row:
                        row = saved_row
                        emit_op(bytes([DW_CFA_restore_state]))
                    else:
                        # Nothing in {CFA, SP, FP, RA} changed inside remember/restore!
                        # If remember_state is only followed by adv, elide the pair.
                        elided = False
                        if rem_idx < len(events) and events[rem_idx] == ("op", bytes([DW_CFA_remember_state])):
                            if all(ev[0] == "adv" for ev in events[rem_idx + 1:]):
                                extra_adv = sum(ev[1] for ev in events[rem_idx + 1:])
                                del events[rem_idx:]
                                pending_adv += extra_adv
                                elided = True
                        if not elided:
                            emit_op(bytes([DW_CFA_restore_state]))
            elif op == DW_CFA_GNU_args_size:
                _, pos = read_uleb128(insns, pos, end)
                ignored_reg_ops += 1
            elif op == DW_CFA_AARCH64_negate_ra_state and arch["name"] == "arm64":
                row["ra_signed"] = not row["ra_signed"]
                emit_op(bytes([DW_CFA_AARCH64_negate_ra_state]))
            elif op == DW_CFA_def_cfa_expression:
                expr_len, pos = read_uleb128(insns, pos, end)
                if pos + expr_len > end:
                    raise ValueError("Truncated def_cfa_expression")
                expr = insns[pos : pos + expr_len]
                pos += expr_len
                # Fixed DRAP / sigframe pattern: DW_OP_breg(FP|SP) <sleb128>, DW_OP_deref
                if (len(expr) >= 3 and expr[-1] == 0x06 and
                    expr[0] in (0x70 + fp_reg, 0x70 + sp_reg)):
                    try:
                        soff, epos = read_sleb128(expr, 1, len(expr) - 1)
                    except ValueError:
                        epos = -1
                    if epos == len(expr) - 1:
                        kind = "fp_indirect" if expr[0] == (0x70 + fp_reg) else "sp_indirect"
                        row["cfa_reg"] = (kind,)
                        row["cfa_off"] = soff
                        emit_op(bytes([DW_CFA_def_cfa_expression]) + encode_uleb128(len(expr)) + expr)
                        continue
                reasons.append(name)
            elif op in (DW_CFA_expression, DW_CFA_val_expression):
                reg, pos = read_uleb128(insns, pos, end)
                expr_len, pos = read_uleb128(insns, pos, end)
                if pos + expr_len > end:
                    raise ValueError("Truncated register expression")
                expr = insns[pos : pos + expr_len]
                pos += expr_len
                if reg == sp_reg:
                    if (op == DW_CFA_expression and len(expr) >= 2 and
                        expr[0] == (0x70 + sp_reg) and row["cfa_reg"] == ("sp_indirect",)):
                        try:
                            soff, epos = read_sleb128(expr, 1, len(expr))
                        except ValueError:
                            epos = -1
                        if epos == len(expr) and soff == row["cfa_off"]:
                            ignored_reg_ops += 1
                            continue
                    reasons.append(f"{name} r{reg}")
                    continue
                if reg not in tracked_regs:
                    ignored_reg_ops += 1
                    continue
                # Fixed DRAP / sigframe save pattern: DW_CFA_expression(FP|RA, DW_OP_breg(FP|SP) <sleb128>)
                if (op == DW_CFA_expression and len(expr) >= 2 and
                    expr[0] in (0x70 + fp_reg, 0x70 + sp_reg)):
                    try:
                        soff, epos = read_sleb128(expr, 1, len(expr))
                    except ValueError:
                        epos = -1
                    if epos == len(expr) and (reg == fp_reg or expr[0] == (0x70 + sp_reg)):
                        kept_reg_ops += 1
                        rule = "fp_off" if expr[0] == (0x70 + fp_reg) else "sp_off"
                        row["fp" if reg == fp_reg else "ra"] = (rule, soff)
                        emit_op(bytes([DW_CFA_expression]) + encode_uleb128(reg) +
                                encode_uleb128(len(expr)) + expr)
                        continue
                reasons.append(f"{name} r{reg}")
            elif op == DW_CFA_register:
                r1, pos = read_uleb128(insns, pos, end)
                r2, pos = read_uleb128(insns, pos, end)
                if r1 in tracked_regs:
                    reasons.append(f"DW_CFA_register r{r1}->r{r2}")
                else:
                    ignored_reg_ops += 1
            elif op == DW_CFA_val_offset:
                r1, pos = read_uleb128(insns, pos, end)
                _, pos = read_uleb128(insns, pos, end)
                if r1 in tracked_regs:
                    reasons.append(f"DW_CFA_val_offset r{r1}")
                else:
                    ignored_reg_ops += 1
            elif op == DW_CFA_val_offset_sf:
                r1, pos = read_uleb128(insns, pos, end)
                _, pos = read_sleb128(insns, pos, end)
                if r1 in tracked_regs:
                    reasons.append(f"DW_CFA_val_offset_sf r{r1}")
                else:
                    ignored_reg_ops += 1
            elif op == DW_CFA_set_loc:
                _, pos = read_encoded_ptr(insns, pos, end, cie["fde_enc"], cie["addr_size"], 0)
                reasons.append("DW_CFA_set_loc")
            else:
                reasons.append(name)
                break
    except (ValueError, struct.error, IndexError) as exc:
        reasons.append(f"malformed_bytecode({exc})")

    # Coalesce consecutive ("adv", d) events and drop trailing ("adv", d)
    while events and events[-1][0] == "adv":
        events.pop()

    min_bytes = bytearray()
    acc_adv = 0
    for kind, payload in events:
        if kind == "adv":
            acc_adv += payload
        else:
            if acc_adv > 0:
                if acc_adv <= 0x3f:
                    min_bytes.append(0x40 | acc_adv)
                elif acc_adv <= 0xff:
                    min_bytes.extend([DW_CFA_advance_loc1, acc_adv])
                elif acc_adv <= 0xffff:
                    min_bytes.append(DW_CFA_advance_loc2)
                    min_bytes.extend(struct.pack("<H", acc_adv))
                else:
                    min_bytes.append(DW_CFA_advance_loc4)
                    min_bytes.extend(struct.pack("<I", acc_adv))
                acc_adv = 0
            min_bytes.extend(payload)

    return {
        "row": row,
        "min_insns": bytes(min_bytes),
        "op_counts": op_counts,
        "ignored_reg_ops": ignored_reg_ops,
        "kept_reg_ops": kept_reg_ops,
        "max_state_depth": max_state_depth,
        "unsupported_reasons": reasons,
    }


def build_minimal_cie_bytes(cie, min_cie_insns, align=4):
    aug = b"zRS\x00" if cie["is_signal"] else b"zR\x00"
    fde_enc = DW_EH_PE_pcrel | DW_EH_PE_sdata4
    body = bytearray()
    body.append(1)  # CIE version 1
    body.extend(aug)
    body.extend(encode_uleb128(cie["code_align"]))
    body.extend(encode_sleb128(cie["data_align"]))
    body.append(cie["ra_reg"])
    body.append(1)  # augmentation data length = 1 ('R')
    body.append(fde_enc)
    body.extend(min_cie_insns)
    # Total record is 4 (length) + 4 (CIE_id=0) + len(body), pad to align
    rem = (8 + len(body)) % align
    if rem:
        body.extend(b"\x00" * (align - rem))
    return struct.pack("<II", 4 + len(body), 0) + bytes(body)


def build_minimal_fde_bytes(min_fde_insns, cie_offset_from_here, init_loc_rel=0, pc_range=0, align=4):
    body = bytearray()
    body.extend(struct.pack("<iI", init_loc_rel, pc_range))
    body.append(0)  # zR augmentation data length = 0
    body.extend(min_fde_insns)
    rem = (8 + len(body)) % align
    if rem:
        body.extend(b"\x00" * (align - rem))
    return struct.pack("<II", 4 + len(body), cie_offset_from_here) + bytes(body)


def analyze_elf(path, out_min_path=None):
    with open(path, "rb") as f:
        data = f.read()

    e_machine, addr_size, sections = parse_elf_sections(data)
    if e_machine not in ARCH_REGS:
        raise ValueError(f"Unsupported ELF e_machine={e_machine}")
    arch = ARCH_REGS[e_machine]

    if ".eh_frame" not in sections:
        print(f"{path}: no .eh_frame section found")
        return

    eh_vaddr, eh_size, eh_buf = sections[".eh_frame"]
    eh_hdr_size = sections.get(".eh_frame_hdr", (0, 0, b""))[1]
    sframe_size = sections.get(".sframe", (0, 0, b""))[1]
    orc_size = (sections.get(".orc_unwind", (0, 0, b""))[1] +
                sections.get(".orc_unwind_ip", (0, 0, b""))[1])
    text_size = sum(sz for name, (_, sz, _) in sections.items() if name.startswith(".text") or name in (".init.text", ".exit.text"))

    cies = {}
    cie_init_rows = {}
    min_eh_stream = bytearray()
    min_cie_offsets = {}

    total_cies = 0
    total_fdes = 0
    supported_fdes = 0
    unsupported_fdes = 0
    unsupported_breakdown = Counter()
    total_op_counts = Counter()
    total_orig_insn_bytes = 0
    total_min_insn_bytes = 0
    total_ignored_ops = 0
    total_kept_ops = 0
    max_depth_seen = 0

    pos = 0
    end = len(eh_buf)
    while pos + 4 <= end:
        length = struct.unpack_from("<I", eh_buf, pos)[0]
        entry_off = pos
        pos += 4
        if length == 0:
            break
        if length == 0xffffffff:
            length = struct.unpack_from("<Q", eh_buf, pos)[0]
            pos += 8
        entry_end = pos + length
        cie_id = struct.unpack_from("<I", eh_buf, pos)[0]

        if cie_id == 0:
            total_cies += 1
            cie = parse_cie(eh_buf, entry_off, pos + 4, entry_end, addr_size, eh_vaddr)
            res = decode_and_minify_insns(cie["insns"], cie, arch, is_cie=True)
            cie["unsupported_reasons"] = list(res["unsupported_reasons"])
            cies[entry_off] = cie
            cie_init_rows[entry_off] = res["row"]
            total_op_counts.update(res["op_counts"])

            cie_key = (cie["code_align"], cie["data_align"], cie["ra_reg"], cie["is_signal"], res["min_insns"])
            if not cie["unsupported_reasons"] and not cie["has_indirect_fde"] and cie_key not in min_cie_offsets:
                min_cie_offsets[cie_key] = len(min_eh_stream)
                min_eh_stream.extend(build_minimal_cie_bytes(cie, res["min_insns"], align=4))
            cie["min_key"] = cie_key
        else:
            total_fdes += 1
            cie_off = pos - cie_id
            cie = cies[cie_off]
            fpos = pos + 4
            init_loc, fpos = read_encoded_ptr(eh_buf, fpos, entry_end, cie["fde_enc"], addr_size, eh_vaddr)
            range_enc = (cie["fde_enc"] & 0x0f) & ~0x08
            pc_range, fpos = read_encoded_ptr(eh_buf, fpos, entry_end, range_enc, addr_size, 0)
            if cie["has_z"]:
                aug_len, fpos = read_uleb128(eh_buf, fpos, entry_end)
                fpos += aug_len
            fde_insns = eh_buf[fpos:entry_end]
            total_orig_insn_bytes += len(fde_insns)

            res = decode_and_minify_insns(fde_insns, cie, arch, init_row=cie_init_rows[cie_off])
            total_op_counts.update(res["op_counts"])
            total_min_insn_bytes += len(res["min_insns"])
            total_ignored_ops += res["ignored_reg_ops"]
            total_kept_ops += res["kept_reg_ops"]
            max_depth_seen = max(max_depth_seen, res["max_state_depth"])

            reasons = list(cie["unsupported_reasons"]) + list(res["unsupported_reasons"])
            if cie["has_indirect_fde"]:
                reasons.append("indirect_fde_encoding")

            if not reasons:
                supported_fdes += 1
                min_cie_off = min_cie_offsets[cie["min_key"]]
                fde_id_pos = len(min_eh_stream) + 4
                init_rel = (init_loc - (eh_vaddr + len(min_eh_stream) + 8)) if eh_vaddr else 0
                if not (-0x80000000 <= init_rel <= 0x7fffffff):
                    init_rel = 0
                min_eh_stream.extend(
                    build_minimal_fde_bytes(res["min_insns"], fde_id_pos - min_cie_off, init_rel, pc_range, align=4)
                )
            else:
                unsupported_fdes += 1
                for r in set(reasons):
                    unsupported_breakdown[r] += 1

        pos = entry_end

    min_eh_stream.extend(b"\x00\x00\x00\x00")  # terminator
    min_eh_hdr_size = 12 + supported_fdes * 8

    if out_min_path:
        with open(out_min_path, "wb") as outf:
            outf.write(min_eh_stream)

    pct_cov = (100.0 * supported_fdes / total_fdes) if total_fdes else 100.0
    orig_total = eh_size + eh_hdr_size
    min_total = len(min_eh_stream) + min_eh_hdr_size
    eh_delta_pct = (100.0 * (len(min_eh_stream) / eh_size - 1.0)) if eh_size else 0.0

    print(f"=== {path} ({arch['name']}) ===")
    print(f"  .text size              : {text_size:10,d} B")
    print(f"  Original .eh_frame      : {eh_size:10,d} B  ({total_cies} CIEs, {total_fdes:,d} FDEs)")
    if eh_hdr_size:
        total_delta_pct = 100.0 * (min_total / orig_total - 1.0)
        print(f"  Original .eh_frame_hdr  : {eh_hdr_size:10,d} B  (combined: {orig_total:,d} B)")
        print(f"  Minified .eh_frame      : {len(min_eh_stream):10,d} B  ({len(min_cie_offsets)} CIEs, {eh_delta_pct:+.1f}% vs .eh_frame)")
        print(f"  Minified + .eh_frame_hdr: {min_total:10,d} B  ({total_delta_pct:+.1f}% combined)")
    else:
        print(f"  Minified .eh_frame      : {len(min_eh_stream):10,d} B  ({len(min_cie_offsets)} CIEs, {eh_delta_pct:+.1f}% vs .eh_frame)")
        print(f"  Simulated .eh_frame_hdr : {min_eh_hdr_size:10,d} B  (linker-generated at final link)")
    print(f"  FDE bytecode payload    : {total_orig_insn_bytes:10,d} B -> {total_min_insn_bytes:,d} B "
          f"(avg {total_min_insn_bytes / max(supported_fdes, 1):.1f} B/FDE)")
    if sframe_size:
        print(f"  .sframe section         : {sframe_size:10,d} B")
    if orc_size:
        print(f"  .orc_unwind + _ip       : {orc_size:10,d} B")
    print(f"  Minimal DWARF coverage  : {supported_fdes:,d} / {total_fdes:,d} FDEs ({pct_cov:.2f}%)")
    print(f"  Register ops kept/skip  : {total_kept_ops:,d} kept (FP/RA), {total_ignored_ops:,d} ignored (other GPRs/args)")
    print(f"  Max remember_state depth: {max_depth_seen}")
    if unsupported_breakdown:
        print("  Unsupported FDE reasons :")
        for r, cnt in unsupported_breakdown.most_common():
            print(f"    - {r}: {cnt}")
    print("  Top DWARF CFA opcodes   :")
    for op_name, cnt in total_op_counts.most_common(10):
        print(f"    - {op_name:34s}: {cnt:8,d}")
    print()


def main():
    epilog = (
        "Examples:\n"
        "  %(prog)s vmlinux\n"
        "  %(prog)s mm/vmscan.o kernel/fork.o\n"
        "  %(prog)s /bin/bash /lib/x86_64-linux-gnu/libc.so.6\n"
        "  %(prog)s --minify /tmp/eh_frame.min mm/vmscan.o\n"
    )
    ap = argparse.ArgumentParser(
        description="Analyze ELF .eh_frame coverage and size for Minimal DWARF CFI",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("files", nargs="+", help="ELF files (.o, .ko, vmlinux, DSO, executable) to analyze")
    ap.add_argument("--minify", metavar="OUT", help="Write minified .eh_frame binary for the first file")
    args = ap.parse_args()

    for idx, path in enumerate(args.files):
        out_p = args.minify if idx == 0 else None
        analyze_elf(path, out_min_path=out_p)


if __name__ == "__main__":
    main()
