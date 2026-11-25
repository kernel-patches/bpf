// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Standalone Multi-Architecture Minimal DWARF CFI Verifier using libLLVM.
 *
 * Entry point and Oracle 1 (libLLVM reference DWARFUnwindTable vs. kernel
 * Minimal DWARF interpreter across both user-stream and kmem paths), with
 * optional compile-time hooks for Oracle 2 (HAVE_VERIFY_INSN) and Oracle 3
 * (HAVE_VERIFY_ORC).
 */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include "llvm/ADT/SmallVector.h"
#include "llvm/BinaryFormat/Dwarf.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/DebugInfo/DWARF/DWARFContext.h"
#include "llvm/DebugInfo/DWARF/DWARFDebugFrame.h"
#include "llvm/DebugInfo/DWARF/LowLevel/DWARFExpression.h"
#include "llvm/DebugInfo/DWARF/LowLevel/DWARFUnwindTable.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCTargetOptions.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"
#pragma GCC diagnostic pop

#include "verify_cfi.hpp"

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>

using namespace llvm;
using namespace llvm::object;

/**
 * getArchSpec() - Populate target architecture metadata from an ELF ObjectFile
 * @Obj: Parsed LLVM ObjectFile under inspection.
 * @Out: Output &struct ArchSpec populated on success.
 *
 * Return: true if @Obj targets a supported architecture (x86_64, aarch64, or
 * riscv64); false otherwise.
 */
static bool getArchSpec(const ObjectFile &Obj, ArchSpec &Out)
{
	auto A = Obj.getArch();
	if (A == Triple::x86_64) {
		Out = {Triple::x86_64, "x86_64-unknown-linux-gnu", "",
		       {8, 7, 6, 16}, 8, true};
		return true;
	}
	if (A == Triple::aarch64) {
		Out = {Triple::aarch64, "aarch64-unknown-linux-gnu",
		       "+v8.5a,+pauth,+bti", {8, 31, 29, 30}, 0, false};
		return true;
	}
	if (A == Triple::riscv64) {
		Out = {Triple::riscv64, "riscv64-unknown-linux-gnu",
		       "+m,+a,+f,+d,+c,+zicsr,+zifencei",
		       {8, 2, 8, 1}, 0, false};
		return true;
	}
	return false;
}

/**
 * rowsEqual() - Compare two evaluated Minimal DWARF unwind rows for equality
 */
bool rowsEqual(const dwarf_cfi_row &a, const dwarf_cfi_row &b)
{
	if (a.cfa_base != b.cfa_base || a.cfa_off != b.cfa_off ||
	    a.sp_rule != b.sp_rule || a.fp_rule != b.fp_rule ||
	    a.ra_rule != b.ra_rule || a.signal != b.signal ||
	    a.ra_signed != b.ra_signed)
		return false;
	if (a.cfa_base == DWARF_CFI_BASE_REG && a.cfa_reg != b.cfa_reg)
		return false;
	if (a.sp_rule == DWARF_CFI_RULE_OFFSET && a.sp_off != b.sp_off)
		return false;
	if ((a.fp_rule == DWARF_CFI_RULE_OFFSET ||
	     a.fp_rule == DWARF_CFI_RULE_FP_OFFSET ||
	     a.fp_rule == DWARF_CFI_RULE_SP_OFFSET) &&
	    a.fp_off != b.fp_off)
		return false;
	if ((a.ra_rule == DWARF_CFI_RULE_OFFSET ||
	     a.ra_rule == DWARF_CFI_RULE_SP_OFFSET) &&
	    a.ra_off != b.ra_off)
		return false;
	return true;
}

void recordIssue(VerifyStats &st, const VerifyOptions &opts,
		 const std::string &reason, const std::string &detail)
{
	uint64_t cnt = ++st.mismatch_reasons[reason];
	if (cnt <= opts.max_samples &&
	    st.sample_issues.size() < opts.max_samples * 8)
		st.sample_issues.push_back("[" + reason + "] " + detail);
}

ArrayRef<uint8_t> findExecBytes(const std::vector<ExecSec> &exec_secs,
				uint64_t addr, uint64_t len)
{
	for (const auto &es : exec_secs) {
		if (addr >= es.vma && len <= es.bytes.size() &&
		    (addr - es.vma) <= es.bytes.size() - len) {
			const uint8_t *p =
				reinterpret_cast<const uint8_t *>(es.bytes.data()) +
				(addr - es.vma);
			return ArrayRef<uint8_t>(p, len);
		}
	}
	return {};
}

/**
 * llvmRowToMinimal() - Convert an LLVM reference UnwindRow to Minimal DWARF
 */
static bool llvmRowToMinimal(const dwarf::UnwindRow &UR, const dwarf::CIE *Cie,
			     const dwarf_cfi_arch &arch, dwarf_cfi_row &out)
{
	memset(&out, 0, sizeof(out));
	out.signal = Cie && Cie->getAugmentationString().contains('S');

	if (arch.ra_reg == 30) {
		if (auto Loc = UR.getRegisterLocations().getRegisterLocation(34)) {
			if (Loc->getLocation() == dwarf::UnwindLocation::Constant)
				out.ra_signed = (Loc->getConstant() != 0);
		}
	}

	const auto &CFA = UR.getCFAValue();
	if (CFA.getLocation() == dwarf::UnwindLocation::RegPlusOffset &&
	    !CFA.getDereference()) {
		uint32_t r = CFA.getRegister();
		if (r > 255)
			return false;
		if (r == arch.sp_reg)
			out.cfa_base = DWARF_CFI_BASE_SP;
		else if (r == arch.fp_reg)
			out.cfa_base = DWARF_CFI_BASE_FP;
		else
			out.cfa_base = DWARF_CFI_BASE_REG;
		out.cfa_reg = (uint8_t)r;
		out.cfa_off = CFA.getOffset();
	} else if (CFA.getLocation() == dwarf::UnwindLocation::DWARFExpr) {
		auto ExprOpt = CFA.getDWARFExpressionBytes();
		if (!ExprOpt)
			return false;
		SmallVector<DWARFExpression::Operation, 4> Ops;
		for (auto &Op : *ExprOpt) {
			if (Op.isError())
				return false;
			Ops.push_back(Op);
		}
		uint8_t breg_fp = dwarf::DW_OP_breg0 + arch.fp_reg;
		uint8_t breg_sp = dwarf::DW_OP_breg0 + arch.sp_reg;
		if (CFA.getDereference() && Ops.size() == 1 &&
		    (Ops[0].getCode() == breg_fp ||
		     Ops[0].getCode() == breg_sp)) {
			out.cfa_base = (Ops[0].getCode() == breg_fp)
					   ? DWARF_CFI_BASE_FP_INDIRECT
					   : DWARF_CFI_BASE_SP_INDIRECT;
			out.cfa_off = (int32_t)(int64_t)Ops[0].getRawOperand(0);
		} else if (!CFA.getDereference() && Ops.size() == 2 &&
			   (Ops[0].getCode() == breg_fp ||
			    Ops[0].getCode() == breg_sp) &&
			   Ops[1].getCode() == dwarf::DW_OP_deref) {
			out.cfa_base = (Ops[0].getCode() == breg_fp)
					   ? DWARF_CFI_BASE_FP_INDIRECT
					   : DWARF_CFI_BASE_SP_INDIRECT;
			out.cfa_off = (int32_t)(int64_t)Ops[0].getRawOperand(0);
		} else {
			return false;
		}
	} else {
		return false;
	}

	auto mapRegRule = [&](uint32_t reg, uint8_t &rule, int32_t &off,
			      bool is_sp, bool is_ra) -> bool {
		auto LocOpt = UR.getRegisterLocations().getRegisterLocation(reg);
		if (!LocOpt) {
			rule = DWARF_CFI_RULE_SAME;
			off = 0;
			return true;
		}
		const auto &L = *LocOpt;
		switch (L.getLocation()) {
		case dwarf::UnwindLocation::Unspecified:
		case dwarf::UnwindLocation::Same:
			rule = DWARF_CFI_RULE_SAME;
			off = 0;
			return true;
		case dwarf::UnwindLocation::Undefined:
			rule = DWARF_CFI_RULE_UNDEFINED;
			off = 0;
			return true;
		case dwarf::UnwindLocation::CFAPlusOffset:
			if (!L.getDereference())
				return false;
			rule = DWARF_CFI_RULE_OFFSET;
			off = L.getOffset();
			return true;
		case dwarf::UnwindLocation::DWARFExpr: {
			if (!L.getDereference())
				return false;
			auto ExprOpt = L.getDWARFExpressionBytes();
			if (!ExprOpt)
				return false;
			SmallVector<DWARFExpression::Operation, 4> Ops;
			for (auto &Op : *ExprOpt) {
				if (Op.isError())
					return false;
				Ops.push_back(Op);
			}
			uint8_t breg_fp = dwarf::DW_OP_breg0 + arch.fp_reg;
			uint8_t breg_sp = dwarf::DW_OP_breg0 + arch.sp_reg;
			if (Ops.size() == 1 &&
			    (Ops[0].getCode() == breg_fp ||
			     Ops[0].getCode() == breg_sp)) {
				int32_t o =
					(int32_t)(int64_t)Ops[0].getRawOperand(0);
				if (is_sp) {
					if (Ops[0].getCode() == breg_sp &&
					    out.cfa_base ==
						    DWARF_CFI_BASE_SP_INDIRECT &&
					    o == out.cfa_off) {
						rule = DWARF_CFI_RULE_SAME;
						off = 0;
						return true;
					}
					return false;
				}
				if (is_ra && Ops[0].getCode() != breg_sp)
					return false;
				rule = (Ops[0].getCode() == breg_fp)
					   ? DWARF_CFI_RULE_FP_OFFSET
					   : DWARF_CFI_RULE_SP_OFFSET;
				off = o;
				return true;
			}
			return false;
		}
		default:
			return false;
		}
	};

	uint32_t ra_col = Cie ? (uint32_t)Cie->getReturnAddressRegister()
			      : arch.ra_reg;
	if (!mapRegRule(arch.fp_reg, out.fp_rule, out.fp_off, false, false))
		return false;
	if (!mapRegRule(ra_col, out.ra_rule, out.ra_off, false, true))
		return false;
	if (!mapRegRule(arch.sp_reg, out.sp_rule, out.sp_off, true, false))
		return false;

	return true;
}

static bool isRelativeEhEncoding(uint8_t enc)
{
	if (enc == dwarf::DW_EH_PE_omit)
		return true;
	uint8_t adj = enc & 0x70;
	return adj == dwarf::DW_EH_PE_pcrel || adj == dwarf::DW_EH_PE_datarel;
}

/**
 * verifyOracle1Dwarf() - Cross-check libLLVM DWARFUnwindTable vs. dwarf_cfi.c
 */
static int verifyOracle1Dwarf(const ObjectFile &Obj, const ArchSpec &AS,
			      uint64_t eh_hdr_vma, StringRef eh_hdr_bytes,
			      uint64_t min_eh_vma, bool can_test_kmem,
			      const std::vector<uint8_t> &kmem_arena,
			      const uint8_t *kmem_hdr,
			      const uint8_t *kmem_eh_start,
			      const uint8_t *kmem_eh_end,
			      const VerifyOptions &opts, VerifyStats &st,
			      std::vector<FDERange> &fde_ranges)
{
	std::unique_ptr<DWARFContext> DCtx = DWARFContext::create(Obj);
	auto EHOrErr = DCtx->getEHFrame();
	if (!EHOrErr) {
		consumeError(EHOrErr.takeError());
		return 1;
	}
	const DWARFDebugFrame *EH = *EHOrErr;

	for (const dwarf::FrameEntry &FE : EH->entries()) {
		const auto *Fde = dyn_cast<dwarf::FDE>(&FE);
		if (!Fde || Fde->getAddressRange() == 0)
			continue;
		st.fdes_total++;

		uint64_t fstart = Fde->getInitialLocation();
		uint64_t fend = fstart + Fde->getAddressRange();

		auto UTOrErr = dwarf::createUnwindTable(Fde);
		if (!UTOrErr) {
			consumeError(UTOrErr.takeError());
			st.fdes_outside_minimal++;
			fde_ranges.push_back({fstart, fend, false, false});
			continue;
		}
		const dwarf::UnwindTable &UT = *UTOrErr;
		if (UT.size() == 0) {
			st.fdes_outside_minimal++;
			fde_ranges.push_back({fstart, fend, false, false});
			continue;
		}

		bool all_rows_minimal = true;
		std::vector<std::pair<uint64_t, dwarf_cfi_row>> exp_rows;
		exp_rows.reserve(UT.size());
		for (size_t i = 0; i < UT.size(); i++) {
			dwarf_cfi_row mr;
			if (!llvmRowToMinimal(UT[i], Fde->getLinkedCIE(),
					      AS.karch, mr)) {
				all_rows_minimal = false;
				break;
			}
			exp_rows.push_back({UT[i].getAddress(), mr});
		}

		if (!all_rows_minimal) {
			st.fdes_outside_minimal++;
			fde_ranges.push_back({fstart, fend, false, false});
			continue;
		}
		st.fdes_minimal_supported++;
		const dwarf::CIE *Cie = Fde->getLinkedCIE();
		bool is_sig = Cie && Cie->getAugmentationString().contains('S');
		bool fde_rel = Cie &&
			       isRelativeEhEncoding(Cie->getFDEPointerEncoding());
		fde_ranges.push_back({fstart, fend, true, is_sig});

		SmallVector<uint64_t, 16> check_pcs;
		check_pcs.push_back(fstart);
		for (auto &pr : exp_rows) {
			if (pr.first >= fstart && pr.first < fend) {
				if (pr.first > fstart)
					check_pcs.push_back(pr.first - 1);
				check_pcs.push_back(pr.first);
			}
		}
		check_pcs.push_back(fend - 1);
		std::sort(check_pcs.begin(), check_pcs.end());
		check_pcs.erase(std::unique(check_pcs.begin(), check_pcs.end()),
				check_pcs.end());

		for (uint64_t pc : check_pcs) {
			const dwarf_cfi_row *exp = &exp_rows[0].second;
			for (auto &pr : exp_rows) {
				if (pr.first <= pc)
					exp = &pr.second;
				else
					break;
			}

			dwarf_cfi_row krow_user{};
			int err_u = dwarf_cfi_unwind_user_eh_frame_hdr(
				(unsigned long)eh_hdr_vma, eh_hdr_bytes.size(),
				(unsigned long)pc, &AS.karch, &krow_user);
			st.fde_pc_checks++;

			if (err_u != 0 || !rowsEqual(krow_user, *exp)) {
				st.llvm_vs_kernel_mismatches++;
				char buf[200];
				snprintf(buf, sizeof(buf),
					 "PC=0x%" PRIx64 " err_u=%d kernel(cfa=%u:%d fp=%u:%d ra=%u:%d)"
					 " llvm(cfa=%u:%d fp=%u:%d ra=%u:%d)",
					 pc, err_u, krow_user.cfa_base,
					 krow_user.cfa_off, krow_user.fp_rule,
					 krow_user.fp_off, krow_user.ra_rule,
					 krow_user.ra_off, exp->cfa_base,
					 exp->cfa_off, exp->fp_rule,
					 exp->fp_off, exp->ra_rule,
					 exp->ra_off);
				recordIssue(st, opts, "llvm_vs_kernel_dwarf",
					    buf);
			}

			if (can_test_kmem && fde_rel) {
				dwarf_cfi_row krow_kmem{};
				uintptr_t base_u =
					reinterpret_cast<uintptr_t>(kmem_arena.data());
				unsigned long kpc = (unsigned long)(
					base_u +
					static_cast<uintptr_t>(pc - min_eh_vma));
				int err_k = dwarf_cfi_unwind_eh_frame_hdr(
					kmem_hdr, eh_hdr_bytes.size(),
					kmem_eh_start, kmem_eh_end, kpc,
					&AS.karch, &krow_kmem);
				st.kmem_pc_checks++;
				if (err_k != err_u ||
				    (err_u == 0 &&
				     !rowsEqual(krow_kmem, krow_user)))
					st.kmem_vs_user_mismatches++;
			}
		}
	}

	std::sort(fde_ranges.begin(), fde_ranges.end(),
		  [](const FDERange &a, const FDERange &b) {
			  return a.start < b.start;
		  });
	return 0;
}

static int verifyFile(const char *path, const VerifyOptions &opts)
{
	auto BufOrErr = MemoryBuffer::getFile(path);
	if (!BufOrErr) {
		errs() << "Failed to open " << path << "\n";
		return 1;
	}
	auto ObjOrErr =
		ObjectFile::createObjectFile(BufOrErr.get()->getMemBufferRef());
	if (!ObjOrErr) {
		consumeError(ObjOrErr.takeError());
		errs() << "Not an object file: " << path << "\n";
		return 1;
	}
	ObjectFile &Obj = *ObjOrErr.get();

	if (Obj.is64Bit() && sizeof(unsigned long) < 8) {
		errs() << path
		       << ": 64-bit ELF verification requires a 64-bit host build\n";
		return 1;
	}

	ArchSpec AS;
	if (!getArchSpec(Obj, AS)) {
		errs() << "Unsupported architecture in " << path << "\n";
		return 1;
	}

	StringRef eh_bytes, eh_hdr_bytes, orc_bytes, orc_ip_bytes;
	uint64_t eh_vma = 0, eh_hdr_vma = 0, orc_ip_vma = 0;
	std::vector<ExecSec> exec_secs;

	for (const SectionRef &Sec : Obj.sections()) {
		Expected<StringRef> NameOrErr = Sec.getName();
		if (!NameOrErr) {
			consumeError(NameOrErr.takeError());
			continue;
		}
		StringRef Name = *NameOrErr;
		Expected<StringRef> DataOrErr = Sec.getContents();
		if (!DataOrErr) {
			consumeError(DataOrErr.takeError());
			continue;
		}
		StringRef Data = *DataOrErr;
		uint64_t Addr = Sec.getAddress();

		if (Name == ".eh_frame") {
			eh_bytes = Data;
			eh_vma = Addr;
		} else if (Name == ".eh_frame_hdr") {
			eh_hdr_bytes = Data;
			eh_hdr_vma = Addr;
		} else if (Name == ".orc_unwind") {
			orc_bytes = Data;
		} else if (Name == ".orc_unwind_ip") {
			orc_ip_bytes = Data;
			orc_ip_vma = Addr;
		}
		if (Sec.isText() && !Data.empty())
			exec_secs.push_back({Name.str(), Addr, Data});
	}

	if (eh_bytes.empty() || eh_hdr_bytes.empty() ||
	    eh_hdr_bytes.size() < 12) {
		errs() << path << ": missing .eh_frame or .eh_frame_hdr\n";
		return 1;
	}

	host_vma_seg segs[2] = {
		{(unsigned long)eh_hdr_vma, eh_hdr_bytes.size(),
		 reinterpret_cast<const uint8_t *>(eh_hdr_bytes.data())},
		{(unsigned long)eh_vma, eh_bytes.size(),
		 reinterpret_cast<const uint8_t *>(eh_bytes.data())},
	};
	host_set_vma_segs(segs, 2);

	uint64_t min_eh_vma = std::min(eh_hdr_vma, eh_vma);
	uint64_t max_eh_end = std::max(eh_hdr_vma + eh_hdr_bytes.size(),
				       eh_vma + eh_bytes.size());
	std::vector<uint8_t> kmem_arena;
	bool can_test_kmem =
		(max_eh_end >= min_eh_vma) &&
		(max_eh_end - min_eh_vma) <= (64ULL * 1024 * 1024) &&
		isRelativeEhEncoding((uint8_t)eh_hdr_bytes[1]) &&
		isRelativeEhEncoding((uint8_t)eh_hdr_bytes[3]);
	const uint8_t *kmem_hdr = nullptr;
	const uint8_t *kmem_eh_start = nullptr;
	const uint8_t *kmem_eh_end = nullptr;
	if (can_test_kmem) {
		kmem_arena.assign(max_eh_end - min_eh_vma, 0);
		memcpy(kmem_arena.data() + (eh_hdr_vma - min_eh_vma),
		       eh_hdr_bytes.data(), eh_hdr_bytes.size());
		memcpy(kmem_arena.data() + (eh_vma - min_eh_vma),
		       eh_bytes.data(), eh_bytes.size());
		kmem_hdr = kmem_arena.data() + (eh_hdr_vma - min_eh_vma);
		kmem_eh_start = kmem_arena.data() + (eh_vma - min_eh_vma);
		kmem_eh_end = kmem_eh_start + eh_bytes.size();
		uintptr_t h_addr = reinterpret_cast<uintptr_t>(kmem_hdr);
		if (h_addr < 0x80000000ULL ||
		    h_addr > UINTPTR_MAX - 0x80000000ULL)
			can_test_kmem = false;
	}

	VerifyStats st;
	std::vector<FDERange> fde_ranges;
	if (verifyOracle1Dwarf(Obj, AS, eh_hdr_vma, eh_hdr_bytes, min_eh_vma,
			       can_test_kmem, kmem_arena, kmem_hdr,
			       kmem_eh_start, kmem_eh_end, opts, st,
			       fde_ranges) != 0) {
		errs() << path << ": LLVM getEHFrame() failed\n";
		return 1;
	}

#if defined(HAVE_VERIFY_INSN) || defined(HAVE_VERIFY_ORC)
	std::string TargetErr;
	const Target *TheTarget =
		TargetRegistry::lookupTarget(AS.triple_str, TargetErr);
	if (!TheTarget) {
		errs() << "lookupTarget failed: " << TargetErr << "\n";
		return 1;
	}

	MCTargetOptions MCOpts;
	std::unique_ptr<MCRegisterInfo> MCRI(
		TheTarget->createMCRegInfo(AS.triple_str));
	std::unique_ptr<MCAsmInfo> MAI(
		TheTarget->createMCAsmInfo(*MCRI, AS.triple_str, MCOpts));
	std::unique_ptr<MCSubtargetInfo> STI(
		TheTarget->createMCSubtargetInfo(AS.triple_str, "",
						 AS.features));
	std::unique_ptr<MCInstrInfo> MCII(TheTarget->createMCInstrInfo());
	std::unique_ptr<MCInstrAnalysis> MIA(
		TheTarget->createMCInstrAnalysis(MCII.get()));
	MCContext Ctx(Triple(AS.triple_str), MAI.get(), MCRI.get(), STI.get());
	std::unique_ptr<MCObjectFileInfo> MOFI(
		TheTarget->createMCObjectFileInfo(Ctx, /*PIC=*/false));
	Ctx.setObjectFileInfo(MOFI.get());
	std::unique_ptr<MCDisassembler> Disasm(
		TheTarget->createMCDisassembler(*STI, Ctx));
	std::unique_ptr<MCInstPrinter> InstPrinter(
		TheTarget->createMCInstPrinter(Triple(AS.triple_str), 0, *MAI,
					       *MCII, *MCRI));

	std::vector<FuncSym> func_syms;
	std::unordered_set<uint64_t> noreturn_addrs;

	auto collectSyms = [&](symbol_iterator begin, symbol_iterator end) {
		for (auto it = begin; it != end; ++it) {
			SymbolRef Sym = *it;
			auto TypeOrErr = Sym.getType();
			auto AddrOrErr = Sym.getAddress();
			auto NameOrErr = Sym.getName();
			if (!TypeOrErr || !AddrOrErr || !NameOrErr) {
				if (!TypeOrErr)
					consumeError(TypeOrErr.takeError());
				if (!AddrOrErr)
					consumeError(AddrOrErr.takeError());
				if (!NameOrErr)
					consumeError(NameOrErr.takeError());
				continue;
			}
			uint64_t addr = *AddrOrErr;
			StringRef name = *NameOrErr;
			if ((AS.llvm_arch == Triple::aarch64 ||
			     AS.llvm_arch == Triple::riscv64) &&
			    (name.starts_with("$x") || name.starts_with("$d")))
				continue;
#ifdef HAVE_VERIFY_INSN
			if (!name.empty() && isKnownNoreturnName(name))
				noreturn_addrs.insert(addr);
#endif
			if (*TypeOrErr == SymbolRef::ST_Function) {
				uint64_t sz = ELFSymbolRef(Sym).getSize();
				func_syms.push_back({addr, sz, name.str()});
			}
		}
	};
	collectSyms(Obj.symbol_begin(), Obj.symbol_end());
	if (const auto *EObj = dyn_cast<ELFObjectFileBase>(&Obj)) {
		auto DynSyms = EObj->getDynamicSymbolIterators();
		collectSyms(DynSyms.begin(), DynSyms.end());
	}

	std::sort(func_syms.begin(), func_syms.end(),
		  [](const FuncSym &a, const FuncSym &b) {
			  return a.addr != b.addr ? a.addr < b.addr
						  : a.size > b.size;
		  });
	func_syms.erase(std::unique(func_syms.begin(), func_syms.end(),
				    [](const FuncSym &a, const FuncSym &b) {
					    return a.addr == b.addr;
				    }),
			func_syms.end());

#ifdef HAVE_VERIFY_INSN
	verifyOracle2Instructions(AS, eh_hdr_vma, eh_hdr_bytes, exec_secs,
				  func_syms, noreturn_addrs, fde_ranges,
				  *Disasm, *MCII, *MCRI, MIA.get(), opts, st);
#endif

#ifdef HAVE_VERIFY_ORC
	if (AS.llvm_arch == Triple::x86_64 && !orc_bytes.empty() &&
	    !orc_ip_bytes.empty()) {
		verifyOracle3Orc(AS, eh_hdr_vma, eh_hdr_bytes, orc_bytes,
				 orc_ip_bytes, orc_ip_vma, exec_secs, func_syms,
				 *Disasm, *STI, *InstPrinter, opts, st);
	}
#else
	(void)orc_bytes;
	(void)orc_ip_bytes;
	(void)orc_ip_vma;
#endif
#else
	(void)orc_bytes;
	(void)orc_ip_bytes;
	(void)orc_ip_vma;
	(void)exec_secs;
#endif

	bool oracle1_fail = (st.llvm_vs_kernel_mismatches > 0 ||
			     st.kmem_vs_user_mismatches > 0);
	bool strict_fail = opts.strict &&
			   (st.insns_cfa_mismatch > 0 ||
			    st.insns_ra_mismatch > 0 ||
			    st.insns_fp_mismatch > 0 ||
			    st.orc_cfa_mismatch > 0 ||
			    st.orc_bp_mismatch > 0);

	if (opts.quiet && !oracle1_fail && !strict_fail) {
		if (st.has_insn_oracle) {
			printf("%s: OK (FDEs: %" PRIu64 "/%" PRIu64
			       ", funcs clean: %" PRIu64 "/%" PRIu64 ")\n",
			       path, st.fdes_minimal_supported, st.fdes_total,
			       st.funcs_clean, st.funcs_verified);
		} else {
			printf("%s: OK (FDEs: %" PRIu64 "/%" PRIu64 ")\n",
			       path, st.fdes_minimal_supported, st.fdes_total);
		}
		fflush(stdout);
		return 0;
	}

	printf("=== %s (%s) ===\n", path, AS.triple_str);
	printf("  [Oracle 1: LLVM Reference DWARF vs Kernel Minimal DWARF]\n");
	printf("    FDEs total / Minimal-supported : %" PRIu64 " / %" PRIu64
	       " (%.2f%%)\n",
	       st.fdes_total, st.fdes_minimal_supported,
	       st.fdes_total ? 100.0 * st.fdes_minimal_supported / st.fdes_total
			     : 0.0);
	printf("    Transition PCs evaluated       : %" PRIu64 "\n",
	       st.fde_pc_checks);
	printf("    LLVM vs Kernel mismatches      : %" PRIu64 "\n",
	       st.llvm_vs_kernel_mismatches);
	if (st.kmem_pc_checks > 0)
		printf("    kmem vs user stream mismatches : %" PRIu64
		       " (%" PRIu64 " PCs)\n",
		       st.kmem_vs_user_mismatches, st.kmem_pc_checks);

	if (st.has_insn_oracle) {
		printf("  [Oracle 2: Machine-Instruction Abstract Execution & Clobber Check]\n");
		printf("    STT_FUNC total / verified      : %" PRIu64
		       " / %" PRIu64 " (no-FDE: %" PRIu64
		       ", split/custom-entry: %" PRIu64 ")\n",
		       st.funcs_total, st.funcs_verified, st.funcs_no_fde,
		       st.funcs_mid_frame_split);
		printf("    Functions 100%% instruction-clean: %" PRIu64
		       " / %" PRIu64 " (%.2f%%)\n",
		       st.funcs_clean, st.funcs_verified,
		       st.funcs_verified
			   ? 100.0 * st.funcs_clean / st.funcs_verified
			   : 0.0);
		printf("    Reachable instructions checked : %" PRIu64
		       " (CFA diff: %" PRIu64 ", RA diff: %" PRIu64
		       ", FP diff: %" PRIu64 ")\n",
		       st.insns_verified, st.insns_cfa_mismatch,
		       st.insns_ra_mismatch, st.insns_fp_mismatch);
	}
	for (const auto &kv : st.mismatch_reasons)
		printf("      - %-28s : %" PRIu64 "\n", kv.first.c_str(),
		       kv.second);
	for (const auto &s : st.sample_issues)
		printf("      sample: %s\n", s.c_str());

	if (st.has_orc) {
		uint64_t denom = st.orc_call_insns - st.orc_no_fde;
		printf("  [Oracle 3: Direct x86-64 ORC (.orc_unwind) vs Kernel Minimal DWARF]\n");
		printf("    ORC_TYPE_CALL insns (with FDE) : %" PRIu64
		       " (no-FDE asm: %" PRIu64 ")\n",
		       denom, st.orc_no_fde);
		printf("    Exact ORC == CFI matches       : %" PRIu64
		       " / %" PRIu64 " (%.4f%%)\n",
		       st.orc_matched, denom,
		       denom ? 100.0 * st.orc_matched / denom : 0.0);
		printf("    ORC diffs (CFA / BP)           : %" PRIu64
		       " / %" PRIu64 "\n",
		       st.orc_cfa_mismatch, st.orc_bp_mismatch);
		for (const auto &s : st.sample_orc_diffs)
			printf("      orc_diff: %s\n", s.c_str());
	}
	printf("\n");
	fflush(stdout);
	return (oracle1_fail || strict_fail) ? 1 : 0;
}

static void printUsage(const char *prog)
{
	printf("Usage: %s [options] <elf_file> [elf_file...]\n"
	       "\n"
	       "Options:\n"
	       "  --strict           Fail (exit 1) on any instruction or ORC diff\n"
	       "                     (Oracle 1 DWARF interpreter mismatches always fail)\n"
	       "  --max-samples <N>  Maximum sample diagnostics per category (default: 6)\n"
	       "  -q, --quiet        Print single-line summary when verification succeeds\n"
	       "  -h, --help         Show this help message\n",
	       prog);
}

int main(int argc, char **argv)
{
	InitLLVM X(argc, argv);
	InitializeAllTargetInfos();
	InitializeAllTargetMCs();
	InitializeAllDisassemblers();

	VerifyOptions opts;
	std::vector<const char *> files;

	for (int i = 1; i < argc; i++) {
		StringRef arg(argv[i]);
		if (arg == "-h" || arg == "--help") {
			printUsage(argv[0]);
			return 0;
		} else if (arg == "--strict") {
			opts.strict = true;
		} else if (arg == "-q" || arg == "--quiet") {
			opts.quiet = true;
		} else if (arg == "--max-samples") {
			if (i + 1 >= argc) {
				errs() << "--max-samples requires an integer argument\n";
				return 1;
			}
			char *endp = nullptr;
			unsigned long v = strtoul(argv[++i], &endp, 10);
			if (!endp || *endp != '\0') {
				errs() << "Invalid --max-samples value: "
				       << argv[i] << "\n";
				return 1;
			}
			opts.max_samples = (size_t)v;
		} else if (arg.starts_with("-")) {
			errs() << "Unknown option: " << arg << "\n";
			printUsage(argv[0]);
			return 1;
		} else {
			files.push_back(argv[i]);
		}
	}

	if (files.empty()) {
		printUsage(argv[0]);
		return 1;
	}

	int rc = 0;
	for (const char *f : files)
		rc |= verifyFile(f, opts);
	return rc;
}
