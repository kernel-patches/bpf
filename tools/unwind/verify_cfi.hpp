/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
#ifndef _TOOLS_UNWIND_VERIFY_CFI_H
#define _TOOLS_UNWIND_VERIFY_CFI_H

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrAnalysis.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/TargetParser/Triple.h"
#pragma GCC diagnostic pop

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <unordered_set>
#include <vector>

#include "dwarf_cfi_host.h"

/**
 * struct VerifyOptions - Command-line configuration for verify_cfi
 * @strict: Return exit status 1 if Oracle 2 or Oracle 3 finds any instruction
 *          or ORC discrepancy (Oracle 1 mismatches always return exit status 1).
 * @quiet: Emit a single-line summary per verified file when no failure occurs.
 * @max_samples: Maximum number of diagnostic mismatch samples printed per kind.
 */
struct VerifyOptions {
	bool strict = false;
	bool quiet = false;
	size_t max_samples = 6;
};

/**
 * struct ArchSpec - Target architecture parameters for LLVM MC and kernel CFI
 * @llvm_arch: LLVM Triple::ArchType identifier.
 * @triple_str: Target triple passed to LLVM TargetRegistry / MCDisassembler.
 * @features: Subtarget feature string enabling ISA extensions in disassembly
 *            (e.g. PAC/BTI on AArch64, compressed RVC on RISC-V).
 * @karch: Kernel DWARF register mapping passed to kernel/unwind/dwarf_cfi.c.
 * @entry_cfa_off: Byte offset from entry SP to caller's SP (8 on x86_64 where
 *                 CALL pushes the 8-byte return address; 0 on arm64/riscv64).
 * @ra_on_entry_stack: True if the return address starts at *(entry_SP + 0)
 *                     rather than in @karch.ra_reg.
 */
struct ArchSpec {
	llvm::Triple::ArchType llvm_arch;
	const char *triple_str;
	const char *features;
	dwarf_cfi_arch karch;
	int32_t entry_cfa_off;
	bool ra_on_entry_stack;
};

/**
 * struct VerifyStats - Aggregated verification counters and diagnostic samples
 */
struct VerifyStats {
	// Oracle 1: LLVM Reference DWARF vs Kernel Minimal DWARF
	uint64_t fdes_total = 0;
	uint64_t fdes_minimal_supported = 0;
	uint64_t fdes_outside_minimal = 0;
	uint64_t fde_pc_checks = 0;
	uint64_t kmem_pc_checks = 0;
	uint64_t kmem_vs_user_mismatches = 0;
	uint64_t llvm_vs_kernel_mismatches = 0;

	// Oracle 2: Instruction Abstract Execution & Clobber Check
	bool has_insn_oracle = false;
	uint64_t funcs_total = 0;
	uint64_t funcs_no_fde = 0;
	uint64_t funcs_mid_frame_split = 0;
	uint64_t funcs_verified = 0;
	uint64_t funcs_clean = 0;
	uint64_t insns_verified = 0;
	uint64_t insns_cfa_mismatch = 0;
	uint64_t insns_ra_mismatch = 0;
	uint64_t insns_fp_mismatch = 0;
	std::map<std::string, uint64_t> mismatch_reasons;
	std::vector<std::string> sample_issues;

	// Oracle 3: ORC vs Kernel Minimal DWARF
	bool has_orc = false;
	uint64_t orc_call_insns = 0;
	uint64_t orc_matched = 0;
	uint64_t orc_no_fde = 0;
	uint64_t orc_cfa_mismatch = 0;
	uint64_t orc_bp_mismatch = 0;
	std::vector<std::string> sample_orc_diffs;
};

struct FDERange {
	uint64_t start;
	uint64_t end;
	bool supported;
	bool signal;
};

struct ExecSec {
	std::string name;
	uint64_t vma;
	llvm::StringRef bytes;
};

struct FuncSym {
	uint64_t addr;
	uint64_t size;
	std::string name;
};

bool rowsEqual(const dwarf_cfi_row &a, const dwarf_cfi_row &b);

void recordIssue(VerifyStats &st, const VerifyOptions &opts,
		 const std::string &reason, const std::string &detail);

llvm::ArrayRef<uint8_t> findExecBytes(const std::vector<ExecSec> &exec_secs,
				      uint64_t addr, uint64_t len);

bool isKnownNoreturnName(llvm::StringRef Name);

void verifyOracle2Instructions(
	const ArchSpec &AS, uint64_t eh_hdr_vma, llvm::StringRef eh_hdr_bytes,
	const std::vector<ExecSec> &exec_secs,
	const std::vector<FuncSym> &func_syms,
	const std::unordered_set<uint64_t> &noreturn_addrs,
	const std::vector<FDERange> &fde_ranges,
	const llvm::MCDisassembler &Disasm, const llvm::MCInstrInfo &MCII,
	const llvm::MCRegisterInfo &MCRI, const llvm::MCInstrAnalysis *MIA,
	const VerifyOptions &opts, VerifyStats &st);

void verifyOracle3Orc(const ArchSpec &AS, uint64_t eh_hdr_vma,
		      llvm::StringRef eh_hdr_bytes, llvm::StringRef orc_bytes,
		      llvm::StringRef orc_ip_bytes, uint64_t orc_ip_vma,
		      const std::vector<ExecSec> &exec_secs,
		      const std::vector<FuncSym> &func_syms,
		      const llvm::MCDisassembler &Disasm,
		      const llvm::MCSubtargetInfo &STI,
		      llvm::MCInstPrinter &InstPrinter,
		      const VerifyOptions &opts, VerifyStats &st);

#endif /* _TOOLS_UNWIND_VERIFY_CFI_H */
