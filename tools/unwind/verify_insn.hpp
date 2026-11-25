/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
#ifndef _TOOLS_UNWIND_VERIFY_INSN_H
#define _TOOLS_UNWIND_VERIFY_INSN_H

#include "verify_cfi.hpp"

/**
 * enum ValKind - Symbolic lattice value kinds tracked in registers and stack
 * @VK_UNKNOWN: Clobbered, runtime-dependent, or unmodeled value.
 * @VK_ENTRY_SP: Value equal to function-entry SP + @off.
 * @VK_ALIGNED_SP: Post-realignment SP + @off (after `and $-align, sp` DRAP).
 * @VK_CALLER_FP: Preserved caller frame pointer value at function entry.
 * @VK_CALLER_RA: Preserved caller return address (@off == 1 when PAC-signed).
 * @VK_CONST: Known 64-bit integer constant (e.g. >4KB frame size setup).
 */
enum ValKind : uint8_t {
	VK_UNKNOWN = 0,
	VK_ENTRY_SP,
	VK_ALIGNED_SP,
	VK_CALLER_FP,
	VK_CALLER_RA,
	VK_CONST,
};

struct SymVal {
	ValKind kind = VK_UNKNOWN;
	int64_t off = 0;

	bool operator==(const SymVal &o) const
	{
		return kind == o.kind && (kind == VK_UNKNOWN || off == o.off);
	}
	bool operator!=(const SymVal &o) const { return !(*this == o); }
};

struct StackKey {
	uint8_t base; // VK_ENTRY_SP or VK_ALIGNED_SP
	int64_t off;
	bool operator<(const StackKey &o) const
	{
		return base != o.base ? base < o.base : off < o.off;
	}
	bool operator==(const StackKey &o) const
	{
		return base == o.base && off == o.off;
	}
};

/**
 * struct AbsState - Per-PC abstract machine state during CFG symbolic execution
 * @regs: Symbolic values of DWARF registers 0..31.
 * @stack: Sparse symbolic stack slots keyed by (ENTRY_SP | ALIGNED_SP) + offset.
 */
struct AbsState {
	SymVal regs[32];
	std::map<StackKey, SymVal> stack;

	SymVal load(const SymVal &addr) const
	{
		if (addr.kind != VK_ENTRY_SP && addr.kind != VK_ALIGNED_SP)
			return {VK_UNKNOWN, 0};
		auto it = stack.find({(uint8_t)addr.kind, addr.off});
		if (it == stack.end())
			return {VK_UNKNOWN, 0};
		return it->second;
	}

	void store(const SymVal &addr, const SymVal &val)
	{
		if (addr.kind != VK_ENTRY_SP && addr.kind != VK_ALIGNED_SP)
			return;
		StackKey k{(uint8_t)addr.kind, addr.off};
		if (val.kind == VK_UNKNOWN)
			stack.erase(k);
		else
			stack[k] = val;
	}
};

int mcRegToDwarf32(const llvm::MCRegisterInfo &MCRI, llvm::MCRegister Reg,
		   llvm::Triple::ArchType Arch);

SymVal addSymImm(SymVal base, int64_t delta);
SymVal addSymVals(SymVal a, SymVal b);
SymVal subSymVals(SymVal a, SymVal b);

void clobberGenericDefs(AbsState &st, const llvm::MCInst &MI,
			const llvm::MCInstrDesc &Desc,
			const llvm::MCRegisterInfo &MCRI,
			const ArchSpec &AS);

bool stepInstruction(AbsState &st, const llvm::MCInst &MI,
		     llvm::StringRef OpName, const llvm::MCInstrDesc &Desc,
		     const llvm::MCRegisterInfo &MCRI, const ArchSpec &AS,
		     uint64_t NextPC, const llvm::MCInstrAnalysis *MIA,
		     uint64_t CurPC, uint64_t InsnSize);

void normalizeRiscvControlFlow(const llvm::MCInst &MI, llvm::StringRef OpName,
			       const llvm::MCRegisterInfo &MCRI,
			       bool &is_ret_or_ind_jump, bool &is_uncond_branch,
			       bool &is_call);

#endif /* _TOOLS_UNWIND_VERIFY_INSN_H */
