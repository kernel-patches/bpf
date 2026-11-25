// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Oracle 3: Direct x86-64 .orc_unwind / .orc_unwind_ip comparison against
 * kernel/unwind/dwarf_cfi.c.
 */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include "llvm/MC/MCInst.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/raw_ostream.h"
#pragma GCC diagnostic pop

#include "verify_cfi.hpp"

#include <algorithm>
#include <cinttypes>
#include <cstdio>

extern "C" {
#include <asm/orc_types.h>
}

using namespace llvm;

/**
 * verifyOracle3Orc() - Cross-check x86-64 .orc_unwind against Minimal DWARF CFI
 * @AS: Target architecture specification (x86_64).
 * @eh_hdr_vma: Virtual address of .eh_frame_hdr.
 * @eh_hdr_bytes: Raw contents of .eh_frame_hdr.
 * @orc_bytes: Raw contents of .orc_unwind (6-byte &struct orc_entry records).
 * @orc_ip_bytes: Raw contents of .orc_unwind_ip (PC-relative s32 offsets).
 * @orc_ip_vma: Virtual address of .orc_unwind_ip.
 * @exec_secs: Executable ELF sections.
 * @func_syms: Deduplicated STT_FUNC symbol list.
 * @Disasm: x86-64 LLVM MCDisassembler.
 * @STI: Target subtarget info for instruction printing.
 * @InstPrinter: Disassembly formatter for mismatch diagnostics.
 * @opts: CLI verification options.
 * @st: Aggregated verification counters and diagnostic samples.
 *
 * Evaluates every instruction inside STT_FUNC symbols whose active ORC record
 * has type %ORC_TYPE_CALL and a defined SP base register, mapping `<asm/
 * orc_types.h>` `ORC_REG_*` encodings directly to `DWARF_CFI_BASE_*` and
 * `DWARF_CFI_RULE_*` fields.
 */
void verifyOracle3Orc(const ArchSpec &AS, uint64_t eh_hdr_vma,
		      StringRef eh_hdr_bytes, StringRef orc_bytes,
		      StringRef orc_ip_bytes, uint64_t orc_ip_vma,
		      const std::vector<ExecSec> &exec_secs,
		      const std::vector<FuncSym> &func_syms,
		      const MCDisassembler &Disasm, const MCSubtargetInfo &STI,
		      MCInstPrinter &InstPrinter, const VerifyOptions &opts,
		      VerifyStats &st)
{
	st.has_orc = true;
	constexpr size_t kOrcEntSz = 6;
	size_t n_orc = orc_bytes.size() / kOrcEntSz;
	size_t n_ip = orc_ip_bytes.size() / 4;
	size_t n = std::min(n_orc, n_ip);
	const uint8_t *orc_raw =
		reinterpret_cast<const uint8_t *>(orc_bytes.data());
	const uint8_t *ip_raw =
		reinterpret_cast<const uint8_t *>(orc_ip_bytes.data());

	std::vector<std::pair<uint64_t, size_t>> sorted_orc;
	sorted_orc.reserve(n);
	for (size_t i = 0; i < n; i++) {
		int32_t rel = (int32_t)support::endian::read32le(ip_raw + i * 4);
		uint64_t epc = orc_ip_vma + i * 4 + (uint64_t)(int64_t)rel;
		sorted_orc.push_back({epc, i});
	}
	std::stable_sort(sorted_orc.begin(), sorted_orc.end(),
			 [](const auto &a, const auto &b) {
				 return a.first < b.first;
			 });

	auto lookupOrcIdx = [&](uint64_t pc, size_t &idx_out) -> bool {
		auto it = std::upper_bound(
			sorted_orc.begin(), sorted_orc.end(), pc,
			[](uint64_t val, const std::pair<uint64_t, size_t> &e) {
				return val < e.first;
			});
		if (it == sorted_orc.begin())
			return false;
		--it;
		idx_out = it->second;
		return true;
	};

	for (const FuncSym &fn : func_syms) {
		if (!fn.size)
			continue;
		ArrayRef<uint8_t> code =
			findExecBytes(exec_secs, fn.addr, fn.size);
		if (code.empty())
			continue;

		uint64_t off = 0;
		while (off < code.size()) {
			uint64_t pc = fn.addr + off;
			MCInst MI;
			uint64_t InsnSize = 0;
			auto DStat = Disasm.getInstruction(
				MI, InsnSize, code.slice(off), pc, nulls());
			if (DStat != MCDisassembler::Success || InsnSize == 0) {
				off++;
				continue;
			}
			off += InsnSize;

			size_t oidx = 0;
			if (!lookupOrcIdx(pc, oidx))
				continue;
			const uint8_t *ep = orc_raw + oidx * kOrcEntSz;
			int16_t sp_offset =
				(int16_t)support::endian::read16le(ep + 0);
			int16_t bp_offset =
				(int16_t)support::endian::read16le(ep + 2);
			uint16_t flags = support::endian::read16le(ep + 4);

			unsigned o_sp_reg = flags & 0xf;
			unsigned o_bp_reg = (flags >> 4) & 0xf;
			unsigned o_type = (flags >> 8) & 0x7;
			if (o_type != ORC_TYPE_CALL ||
			    o_sp_reg == ORC_REG_UNDEFINED)
				continue;

			st.orc_call_insns++;
			dwarf_cfi_row row{};
			if (dwarf_cfi_unwind_user_eh_frame_hdr(
				    (unsigned long)eh_hdr_vma,
				    eh_hdr_bytes.size(), (unsigned long)pc,
				    &AS.karch, &row) != 0) {
				st.orc_no_fde++;
				continue;
			}

			bool cfa_ok = false;
			if (o_sp_reg == ORC_REG_SP) {
				cfa_ok = (row.cfa_base == DWARF_CFI_BASE_SP &&
					  row.cfa_off == sp_offset);
			} else if (o_sp_reg == ORC_REG_BP) {
				cfa_ok = (row.cfa_base == DWARF_CFI_BASE_FP &&
					  row.cfa_off == sp_offset);
			} else if (o_sp_reg == ORC_REG_BP_INDIRECT) {
				cfa_ok = (row.cfa_base ==
						  DWARF_CFI_BASE_FP_INDIRECT &&
					  row.cfa_off == sp_offset);
			} else if (o_sp_reg == ORC_REG_SP_INDIRECT) {
				cfa_ok = (row.cfa_base ==
						  DWARF_CFI_BASE_SP_INDIRECT &&
					  row.cfa_off == sp_offset);
			} else if (row.cfa_base == DWARF_CFI_BASE_REG) {
				int exp_dreg = (o_sp_reg == ORC_REG_AX) ? 0 :
					       (o_sp_reg == ORC_REG_DX) ? 1 :
					       (o_sp_reg == ORC_REG_DI) ? 5 :
					       (o_sp_reg == ORC_REG_R10) ? 10 :
					       (o_sp_reg == ORC_REG_R13) ? 13 :
					       -1;
				cfa_ok = (row.cfa_reg == exp_dreg &&
					  row.cfa_off == sp_offset);
			}

			bool bp_ok = false;
			if (o_bp_reg == ORC_REG_UNDEFINED) {
				bp_ok = (row.fp_rule == DWARF_CFI_RULE_SAME);
			} else if (o_bp_reg == ORC_REG_PREV_SP) {
				bp_ok = (row.fp_rule == DWARF_CFI_RULE_OFFSET &&
					 row.fp_off == bp_offset);
			} else if (o_bp_reg == ORC_REG_BP) {
				bp_ok = (row.fp_rule ==
						 DWARF_CFI_RULE_FP_OFFSET &&
					 row.fp_off == bp_offset);
			}

			if (cfa_ok && bp_ok) {
				st.orc_matched++;
			} else {
				if (!cfa_ok)
					st.orc_cfa_mismatch++;
				if (!bp_ok)
					st.orc_bp_mismatch++;
				if (st.sample_orc_diffs.size() <
				    opts.max_samples * 3) {
					std::string dis_str;
					raw_string_ostream rso(dis_str);
					InstPrinter.printInst(&MI, pc, "", STI,
							      rso);
					char b[256];
					snprintf(b, sizeof(b),
						 "%s+0x%" PRIx64 " (0x%" PRIx64
						 ")%s | ORC(sp=%u:%+d bp=%u:%+d)"
						 " vs CFI(cfa=%u:%+d fp=%u:%+d)",
						 fn.name.c_str(), pc - fn.addr,
						 pc, rso.str().c_str(), o_sp_reg,
						 sp_offset, o_bp_reg, bp_offset,
						 row.cfa_base, row.cfa_off,
						 row.fp_rule, row.fp_off);
					st.sample_orc_diffs.push_back(b);
				}
			}
		}
	}
}
