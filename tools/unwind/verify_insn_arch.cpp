// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Per-architecture Tier-2 symbolic instruction lifters (x86_64, arm64, riscv64)
 * and Tier-1 generic MCInstrDesc register-def clobber fallback for verify_cfi.
 */

#include "verify_insn.hpp"

using namespace llvm;

/**
 * mcRegToDwarf32() - Map an LLVM physical MCRegister to DWARF reg 0..31
 * @MCRI: Target MCRegisterInfo table.
 * @Reg: Physical register operand from an MCInst.
 * @Arch: Target architecture type.
 *
 * Resolves both full-width registers and sub-registers (e.g. %eax -> %rax on
 * x86_64, w29 -> x29 on AArch64) via super-register traversal. On AArch64,
 * LLVM's getDwarfRegNum() maps both XZR/WZR (zero sink) and SP/WSP to DWARF
 * number 31 because they share architectural 5-bit encoding 31 in different
 * instruction classes; XZR and WZR are explicitly filtered out so flag-setting
 * compares (`cmp` -> `SUBS XZR, ...`) never clobber the stack pointer.
 *
 * Return: DWARF register number in [0, 31], or -1 if unmapped / zero sink.
 */
int mcRegToDwarf32(const MCRegisterInfo &MCRI, MCRegister Reg,
		   Triple::ArchType Arch)
{
	if (!Reg.isValid() || Reg.id() == 0)
		return -1;
	if (Arch == Triple::aarch64) {
		StringRef N = MCRI.getName(Reg);
		if (N == "XZR" || N == "WZR")
			return -1;
	}
	int64_t d = MCRI.getDwarfRegNum(Reg, /*isEH=*/true);
	if (d >= 0 && d < 32)
		return (int)d;
	for (MCPhysReg Super : MCRI.superregs(Reg)) {
		if (Arch == Triple::aarch64) {
			StringRef SN = MCRI.getName(Super);
			if (SN == "XZR" || SN == "WZR")
				continue;
		}
		int64_t sd = MCRI.getDwarfRegNum(Super, /*isEH=*/true);
		if (sd >= 0 && sd < 32)
			return (int)sd;
	}
	return -1;
}

SymVal addSymImm(SymVal base, int64_t delta)
{
	if (base.kind == VK_ENTRY_SP || base.kind == VK_ALIGNED_SP ||
	    base.kind == VK_CONST)
		return {base.kind, (int64_t)((uint64_t)base.off + (uint64_t)delta)};
	return {VK_UNKNOWN, 0};
}

SymVal addSymVals(SymVal a, SymVal b)
{
	if (a.kind == VK_CONST && b.kind == VK_CONST)
		return {VK_CONST, (int64_t)((uint64_t)a.off + (uint64_t)b.off)};
	if ((a.kind == VK_ENTRY_SP || a.kind == VK_ALIGNED_SP) &&
	    b.kind == VK_CONST)
		return {a.kind, (int64_t)((uint64_t)a.off + (uint64_t)b.off)};
	if (a.kind == VK_CONST &&
	    (b.kind == VK_ENTRY_SP || b.kind == VK_ALIGNED_SP))
		return {b.kind, (int64_t)((uint64_t)b.off + (uint64_t)a.off)};
	return {VK_UNKNOWN, 0};
}

SymVal subSymVals(SymVal a, SymVal b)
{
	if (b.kind == VK_CONST)
		return addSymVals(a, {VK_CONST, (int64_t)(-(uint64_t)b.off)});
	return {VK_UNKNOWN, 0};
}

/**
 * clobberGenericDefs() - Tier-1 conservative register-def clobber fallback
 * @st: Abstract state updated in place.
 * @MI: Decoded LLVM MCInst.
 * @Desc: Instruction descriptor providing explicit/implicit register defs.
 * @MCRI: Target register alias hierarchy.
 * @AS: Target architecture specification.
 *
 * Marks every architectural DWARF register (0..31) modified by @MI (explicit
 * def operands, implicit defs, and sub-/super-register aliases) as VK_UNKNOWN,
 * and clobbers ABI caller-saved registers across call instructions.
 */
void clobberGenericDefs(AbsState &st, const MCInst &MI, const MCInstrDesc &Desc,
			const MCRegisterInfo &MCRI, const ArchSpec &AS)
{
	auto clobberPhys = [&](MCRegister R) {
		if (!R.isValid() || R.id() == 0)
			return;
		if (AS.llvm_arch == Triple::aarch64) {
			StringRef RN = MCRI.getName(R);
			if (RN == "XZR" || RN == "WZR")
				return;
		}
		for (MCPhysReg Alias : MCRI.sub_and_superregs_inclusive(R)) {
			if (AS.llvm_arch == Triple::aarch64) {
				StringRef AN = MCRI.getName(Alias);
				if (AN == "XZR" || AN == "WZR")
					continue;
			}
			int64_t d = MCRI.getDwarfRegNum(Alias, /*isEH=*/true);
			if (d >= 0 && d < 32) {
				if (AS.llvm_arch == Triple::riscv64 && d == 0)
					continue;
				st.regs[d] = {VK_UNKNOWN, 0};
			}
		}
	};

	unsigned numDefs = Desc.getNumDefs();
	for (unsigned i = 0; i < numDefs && i < MI.getNumOperands(); i++) {
		if (MI.getOperand(i).isReg())
			clobberPhys(MI.getOperand(i).getReg());
	}
	for (MCPhysReg Imp : Desc.implicit_defs())
		clobberPhys(Imp);

	if (Desc.isCall()) {
		for (int d = 0; d < 32; d++) {
			if (AS.llvm_arch == Triple::x86_64) {
				if (d == 3 || d == 6 || d == 7 ||
				    (d >= 12 && d <= 15))
					continue;
				st.regs[d] = {VK_UNKNOWN, 0};
			} else if (AS.llvm_arch == Triple::aarch64) {
				if ((d >= 19 && d <= 29) || d == 31)
					continue;
				st.regs[d] = {VK_UNKNOWN, 0};
			} else if (AS.llvm_arch == Triple::riscv64) {
				if (d == 0 || d == 2 || d == 3 || d == 4 ||
				    d == 8 || d == 9 || (d >= 18 && d <= 27))
					continue;
				st.regs[d] = {VK_UNKNOWN, 0};
			}
		}
	}
}

struct InsnStepCtx {
	const MCInst &MI;
	const MCRegisterInfo &MCRI;
	const ArchSpec &AS;
	const MCInstrAnalysis *MIA;
	uint64_t CurPC;
	uint64_t NextPC;
	uint64_t InsnSize;

	int regD(unsigned idx) const
	{
		if (idx >= MI.getNumOperands() || !MI.getOperand(idx).isReg())
			return -1;
		return mcRegToDwarf32(MCRI, MI.getOperand(idx).getReg(),
				      AS.llvm_arch);
	}

	SymVal getRegVal(const AbsState &st, int d) const
	{
		if (d < 0 || d >= 32)
			return {VK_UNKNOWN, 0};
		if (AS.llvm_arch == Triple::riscv64 && d == 0)
			return {VK_CONST, 0};
		return st.regs[d];
	}

	void setRegVal(AbsState &st, int d, SymVal v) const
	{
		if (d < 0 || d >= 32)
			return;
		if (AS.llvm_arch == Triple::riscv64 && d == 0)
			return;
		st.regs[d] = v;
	}
};

/**
 * stepInstructionX86() - Tier-2 symbolic lifter for x86-64 frame instructions
 * @st: Abstract register/stack state updated in place.
 * @OpName: LLVM MC opcode name (e.g. "PUSH64r", "SUB64ri8", "LEA64r").
 * @Desc: Instruction descriptor.
 * @ctx: Disassembled instruction context.
 *
 * Models x86-64 prologue, epilogue, DRAP (`lea 8(%rsp), %r10; and $-64, %rsp;
 * pushq -8(%r10)`), frame-pointer (`push %rbp; mov %rsp, %rbp; leave`), and
 * PIC `call next_pc` stack effects.
 *
 * Return: true if @OpName was modeled; false to trigger generic clobbering.
 */
static bool stepInstructionX86(AbsState &st, StringRef OpName,
			       const MCInstrDesc &Desc, const InsnStepCtx &ctx)
{
	const MCInst &MI = ctx.MI;

	if (Desc.isCall()) {
		uint64_t Target = 0;
		if (ctx.MIA &&
		    ctx.MIA->evaluateBranch(MI, ctx.CurPC, ctx.InsnSize,
					    Target) &&
		    Target == ctx.NextPC) {
			st.regs[7] = addSymImm(st.regs[7], -8);
			st.store(st.regs[7], {VK_UNKNOWN, 0});
			return true;
		}
		clobberGenericDefs(st, MI, Desc, ctx.MCRI, ctx.AS);
		return true;
	}
	if (OpName.starts_with("PUSH64r")) {
		int src = ctx.regD(0);
		st.regs[7] = addSymImm(st.regs[7], -8);
		st.store(st.regs[7], ctx.getRegVal(st, src));
		return true;
	}
	if (OpName == "PUSHF64" || OpName.starts_with("PUSH64i") ||
	    OpName == "PUSH64rmm" || OpName == "PUSH64rmr") {
		st.regs[7] = addSymImm(st.regs[7], -8);
		st.store(st.regs[7], {VK_UNKNOWN, 0});
		return true;
	}
	if (OpName.starts_with("POP64r")) {
		int dst = ctx.regD(0);
		SymVal loaded = st.load(st.regs[7]);
		st.regs[7] = addSymImm(st.regs[7], 8);
		if (dst != 7)
			ctx.setRegVal(st, dst, loaded);
		return true;
	}
	if (OpName == "POPF64" || OpName == "POP64rmm") {
		st.regs[7] = addSymImm(st.regs[7], 8);
		return true;
	}
	if (OpName == "LEAVE64") {
		st.regs[7] = st.regs[6];
		st.regs[6] = st.load(st.regs[7]);
		st.regs[7] = addSymImm(st.regs[7], 8);
		return true;
	}
	if (OpName == "MOV64rr" || OpName == "MOV64rr_REV") {
		ctx.setRegVal(st, ctx.regD(0), ctx.getRegVal(st, ctx.regD(1)));
		return true;
	}
	if (OpName == "MOV32ri" || OpName == "MOV64ri" ||
	    OpName == "MOV64ri32") {
		int dst = ctx.regD(0);
		if (MI.getNumOperands() >= 2 && MI.getOperand(1).isImm()) {
			int64_t imm = MI.getOperand(1).getImm();
			if (OpName == "MOV32ri")
				imm = (uint32_t)imm;
			ctx.setRegVal(st, dst, {VK_CONST, imm});
			return true;
		}
	}
	if (OpName == "XOR32rr" || OpName == "XOR64rr") {
		int dst = ctx.regD(0), s1 = ctx.regD(1), s2 = ctx.regD(2);
		if (s1 >= 0 && s1 == s2) {
			ctx.setRegVal(st, dst, {VK_CONST, 0});
			return true;
		}
	}
	if ((OpName == "ADD64ri8" || OpName == "ADD64ri32" ||
	     OpName == "SUB64ri8" || OpName == "SUB64ri32") &&
	    MI.getNumOperands() >= 3 && MI.getOperand(2).isImm()) {
		int dst = ctx.regD(0), src = ctx.regD(1);
		int64_t imm = MI.getOperand(2).getImm();
		if (OpName.starts_with("SUB"))
			imm = (int64_t)(-(uint64_t)imm);
		ctx.setRegVal(st, dst, addSymImm(ctx.getRegVal(st, src), imm));
		return true;
	}
	if (OpName == "ADD64rr" || OpName == "SUB64rr") {
		int dst = ctx.regD(0), s1 = ctx.regD(1), s2 = ctx.regD(2);
		ctx.setRegVal(st, dst,
			      OpName == "ADD64rr"
				  ? addSymVals(ctx.getRegVal(st, s1),
					       ctx.getRegVal(st, s2))
				  : subSymVals(ctx.getRegVal(st, s1),
					       ctx.getRegVal(st, s2)));
		return true;
	}
	if ((OpName == "AND64ri8" || OpName == "AND64ri32") &&
	    MI.getNumOperands() >= 3 && MI.getOperand(2).isImm()) {
		int dst = ctx.regD(0), src = ctx.regD(1);
		int64_t mask = MI.getOperand(2).getImm();
		if (dst == 7 && src == 7 && mask < 0 && (mask & 0x7) == 0) {
			st.regs[7] = {VK_ALIGNED_SP, 0};
			return true;
		}
	}
	if (OpName == "LEA64r" && MI.getNumOperands() >= 6) {
		int dst = ctx.regD(0), base = ctx.regD(1), idx = ctx.regD(3);
		if (base >= 0 && MI.getOperand(2).isImm() &&
		    MI.getOperand(2).getImm() == 1 && idx < 0 &&
		    MI.getOperand(4).isImm()) {
			ctx.setRegVal(st, dst,
				      addSymImm(ctx.getRegVal(st, base),
						MI.getOperand(4).getImm()));
			return true;
		}
	}
	if (OpName == "MOV64mr" && MI.getNumOperands() >= 6) {
		int base = ctx.regD(0), idx = ctx.regD(2), src = ctx.regD(5);
		if (base >= 0 && MI.getOperand(1).isImm() &&
		    MI.getOperand(1).getImm() == 1 && idx < 0 &&
		    MI.getOperand(3).isImm()) {
			st.store(addSymImm(ctx.getRegVal(st, base),
					   MI.getOperand(3).getImm()),
				 ctx.getRegVal(st, src));
			return true;
		}
	}
	if (OpName == "MOV64rm" && MI.getNumOperands() >= 6) {
		int dst = ctx.regD(0), base = ctx.regD(1), idx = ctx.regD(3);
		if (base >= 0 && MI.getOperand(2).isImm() &&
		    MI.getOperand(2).getImm() == 1 && idx < 0 &&
		    MI.getOperand(4).isImm()) {
			ctx.setRegVal(st, dst,
				      st.load(addSymImm(ctx.getRegVal(st, base),
							MI.getOperand(4).getImm())));
			return true;
		}
	}
	return false;
}

/**
 * stepInstructionArm64() - Tier-2 symbolic lifter for AArch64 instructions
 * @st: Abstract register/stack state updated in place.
 * @OpName: LLVM MC opcode name (e.g. "STPXpre", "LDPXi", "PACIASP").
 * @ctx: Disassembled instruction context.
 *
 * Models AAPCS64 frame setup and teardown including Pointer Authentication
 * (`paciasp`/`autiasp`), >4KB stack-frame constant materialization, and paired
 * or single stack spills/reloads.
 *
 * Return: true if @OpName was modeled; false to trigger generic clobbering.
 */
static bool stepInstructionArm64(AbsState &st, StringRef OpName,
				 const InsnStepCtx &ctx)
{
	const MCInst &MI = ctx.MI;

	if (OpName == "PACIASP" || OpName == "PACIBSP" ||
	    OpName == "AUTIASP" || OpName == "AUTIBSP") {
		if (st.regs[30].kind == VK_CALLER_RA)
			st.regs[30].off ^= 1;
		return true;
	}
	if (OpName == "HINT" && MI.getNumOperands() >= 1 &&
	    MI.getOperand(0).isImm()) {
		int64_t h = MI.getOperand(0).getImm();
		if (h == 25 || h == 27 || h == 29 || h == 31) {
			if (st.regs[30].kind == VK_CALLER_RA)
				st.regs[30].off ^= 1;
			return true;
		}
	}
	if ((OpName == "ADDXri" || OpName == "SUBXri") &&
	    MI.getNumOperands() >= 4 && MI.getOperand(2).isImm() &&
	    MI.getOperand(3).isImm()) {
		int dst = ctx.regD(0), src = ctx.regD(1);
		unsigned sh = (unsigned)MI.getOperand(3).getImm() & 0x3f;
		int64_t imm = (int64_t)((uint64_t)MI.getOperand(2).getImm() << sh);
		if (OpName == "SUBXri")
			imm = (int64_t)(-(uint64_t)imm);
		ctx.setRegVal(st, dst, addSymImm(ctx.getRegVal(st, src), imm));
		return true;
	}
	if (OpName == "ORRXrs" && MI.getNumOperands() >= 4 &&
	    MI.getOperand(3).isImm() && MI.getOperand(3).getImm() == 0) {
		if (MI.getOperand(1).isReg() &&
		    StringRef(ctx.MCRI.getName(MI.getOperand(1).getReg())) == "XZR") {
			ctx.setRegVal(st, ctx.regD(0),
				      ctx.getRegVal(st, ctx.regD(2)));
			return true;
		}
	}
	if (OpName == "MOVZXi" && MI.getNumOperands() >= 3 &&
	    MI.getOperand(1).isImm() && MI.getOperand(2).isImm()) {
		unsigned sh = (unsigned)MI.getOperand(2).getImm() & 0x3f;
		uint64_t v = ((uint64_t)MI.getOperand(1).getImm()) << sh;
		ctx.setRegVal(st, ctx.regD(0), {VK_CONST, (int64_t)v});
		return true;
	}
	if (OpName == "MOVNXi" && MI.getNumOperands() >= 3 &&
	    MI.getOperand(1).isImm() && MI.getOperand(2).isImm()) {
		unsigned sh = (unsigned)MI.getOperand(2).getImm() & 0x3f;
		uint64_t v = ~(((uint64_t)MI.getOperand(1).getImm()) << sh);
		ctx.setRegVal(st, ctx.regD(0), {VK_CONST, (int64_t)v});
		return true;
	}
	if (OpName == "MOVKXi" && MI.getNumOperands() >= 4 &&
	    MI.getOperand(2).isImm() && MI.getOperand(3).isImm()) {
		SymVal cur = ctx.getRegVal(st, ctx.regD(1));
		if (cur.kind == VK_CONST) {
			unsigned sh = (unsigned)MI.getOperand(3).getImm() & 0x3f;
			uint64_t u = ((uint64_t)cur.off & ~(0xffffULL << sh)) |
				     (((uint64_t)MI.getOperand(2).getImm() &
				       0xffffULL) << sh);
			ctx.setRegVal(st, ctx.regD(0), {VK_CONST, (int64_t)u});
			return true;
		}
	}
	if ((OpName == "ADDXrs" || OpName == "SUBXrs" ||
	     OpName == "ADDXrx" || OpName == "SUBXrx") &&
	    MI.getNumOperands() >= 4 && MI.getOperand(3).isImm()) {
		int dst = ctx.regD(0), s1 = ctx.regD(1), s2 = ctx.regD(2);
		SymVal v2 = ctx.getRegVal(st, s2);
		int64_t imm_arg = MI.getOperand(3).getImm();
		bool ok_shift = false;
		if (OpName.ends_with("rs") && (imm_arg & ~0x3f) == 0) {
			if (v2.kind == VK_CONST)
				v2.off = (int64_t)((uint64_t)v2.off << imm_arg);
			ok_shift = (imm_arg == 0 || v2.kind == VK_CONST);
		} else if (OpName.ends_with("rx") &&
			   ((imm_arg >> 3) == 3 || (imm_arg >> 3) == 7) &&
			   (imm_arg & 7) == 0) {
			ok_shift = true;
		}
		if (ok_shift) {
			ctx.setRegVal(st, dst,
				      OpName.starts_with("ADD")
					  ? addSymVals(ctx.getRegVal(st, s1), v2)
					  : subSymVals(ctx.getRegVal(st, s1), v2));
			return true;
		}
	}
	if (OpName == "ANDXri" && ctx.regD(0) == 31) {
		st.regs[31] = {VK_ALIGNED_SP, 0};
		return true;
	}

	auto scaleOf = [](StringRef N) -> int64_t {
		if (N.contains("Q"))
			return 16;
		if (N.contains("X") || N.contains("D"))
			return 8;
		if (N.contains("W") || N.contains("S"))
			return 4;
		if (N.contains("H"))
			return 2;
		return 1;
	};

	if ((OpName == "STPXpre" || OpName == "STPWpre" ||
	     OpName == "STPDpre" || OpName == "STPQpre") &&
	    MI.getNumOperands() >= 5 && MI.getOperand(4).isImm()) {
		int wb = ctx.regD(0), r1 = ctx.regD(1), r2 = ctx.regD(2);
		int base = ctx.regD(3);
		SymVal addr = addSymImm(ctx.getRegVal(st, base),
					MI.getOperand(4).getImm() * scaleOf(OpName));
		ctx.setRegVal(st, wb, addr);
		if (OpName == "STPXpre") {
			st.store(addr, ctx.getRegVal(st, r1));
			st.store(addSymImm(addr, 8), ctx.getRegVal(st, r2));
		}
		return true;
	}
	if ((OpName == "STPXpost" || OpName == "STPWpost" ||
	     OpName == "STPDpost" || OpName == "STPQpost") &&
	    MI.getNumOperands() >= 5 && MI.getOperand(4).isImm()) {
		int wb = ctx.regD(0), r1 = ctx.regD(1), r2 = ctx.regD(2);
		int base = ctx.regD(3);
		SymVal addr = ctx.getRegVal(st, base);
		if (OpName == "STPXpost") {
			st.store(addr, ctx.getRegVal(st, r1));
			st.store(addSymImm(addr, 8), ctx.getRegVal(st, r2));
		}
		ctx.setRegVal(st, wb,
			      addSymImm(addr,
					MI.getOperand(4).getImm() * scaleOf(OpName)));
		return true;
	}
	if (OpName == "STPXi" && MI.getNumOperands() >= 4 &&
	    MI.getOperand(3).isImm()) {
		int r1 = ctx.regD(0), r2 = ctx.regD(1), base = ctx.regD(2);
		SymVal addr = addSymImm(ctx.getRegVal(st, base),
					MI.getOperand(3).getImm() * 8);
		st.store(addr, ctx.getRegVal(st, r1));
		st.store(addSymImm(addr, 8), ctx.getRegVal(st, r2));
		return true;
	}
	if ((OpName == "LDPXpost" || OpName == "LDPWpost" ||
	     OpName == "LDPDpost" || OpName == "LDPQpost") &&
	    MI.getNumOperands() >= 5 && MI.getOperand(4).isImm()) {
		int wb = ctx.regD(0), r1 = ctx.regD(1), r2 = ctx.regD(2);
		int base = ctx.regD(3);
		SymVal addr = ctx.getRegVal(st, base);
		SymVal v1 = st.load(addr), v2 = st.load(addSymImm(addr, 8));
		ctx.setRegVal(st, wb,
			      addSymImm(addr,
					MI.getOperand(4).getImm() * scaleOf(OpName)));
		if (OpName == "LDPXpost") {
			ctx.setRegVal(st, r1, v1);
			ctx.setRegVal(st, r2, v2);
		} else {
			if (r1 >= 0)
				ctx.setRegVal(st, r1, {VK_UNKNOWN, 0});
			if (r2 >= 0)
				ctx.setRegVal(st, r2, {VK_UNKNOWN, 0});
		}
		return true;
	}
	if ((OpName == "LDPXpre" || OpName == "LDPWpre" ||
	     OpName == "LDPDpre" || OpName == "LDPQpre") &&
	    MI.getNumOperands() >= 5 && MI.getOperand(4).isImm()) {
		int wb = ctx.regD(0), r1 = ctx.regD(1), r2 = ctx.regD(2);
		int base = ctx.regD(3);
		SymVal addr = addSymImm(ctx.getRegVal(st, base),
					MI.getOperand(4).getImm() * scaleOf(OpName));
		ctx.setRegVal(st, wb, addr);
		if (OpName == "LDPXpre") {
			ctx.setRegVal(st, r1, st.load(addr));
			ctx.setRegVal(st, r2, st.load(addSymImm(addr, 8)));
		} else {
			if (r1 >= 0)
				ctx.setRegVal(st, r1, {VK_UNKNOWN, 0});
			if (r2 >= 0)
				ctx.setRegVal(st, r2, {VK_UNKNOWN, 0});
		}
		return true;
	}
	if (OpName == "LDPXi" && MI.getNumOperands() >= 4 &&
	    MI.getOperand(3).isImm()) {
		int r1 = ctx.regD(0), r2 = ctx.regD(1), base = ctx.regD(2);
		SymVal addr = addSymImm(ctx.getRegVal(st, base),
					MI.getOperand(3).getImm() * 8);
		SymVal v1 = st.load(addr), v2 = st.load(addSymImm(addr, 8));
		ctx.setRegVal(st, r1, v1);
		ctx.setRegVal(st, r2, v2);
		return true;
	}
	if ((OpName == "STRXpre" || OpName == "STRWpre" ||
	     OpName == "STRQpre" || OpName == "STRDpre" ||
	     OpName == "STRBpre" || OpName == "STRHpre") &&
	    MI.getNumOperands() >= 4 && MI.getOperand(3).isImm()) {
		int wb = ctx.regD(0), rt = ctx.regD(1), base = ctx.regD(2);
		SymVal addr = addSymImm(ctx.getRegVal(st, base),
					MI.getOperand(3).getImm());
		ctx.setRegVal(st, wb, addr);
		if (OpName == "STRXpre")
			st.store(addr, ctx.getRegVal(st, rt));
		return true;
	}
	if ((OpName == "STRXpost" || OpName == "STRWpost" ||
	     OpName == "STRQpost" || OpName == "STRDpost" ||
	     OpName == "STRBpost" || OpName == "STRHpost") &&
	    MI.getNumOperands() >= 4 && MI.getOperand(3).isImm()) {
		int wb = ctx.regD(0), rt = ctx.regD(1), base = ctx.regD(2);
		SymVal addr = ctx.getRegVal(st, base);
		if (OpName == "STRXpost")
			st.store(addr, ctx.getRegVal(st, rt));
		ctx.setRegVal(st, wb,
			      addSymImm(addr, MI.getOperand(3).getImm()));
		return true;
	}
	if ((OpName == "LDRXpost" || OpName == "LDRWpost" ||
	     OpName == "LDRQpost" || OpName == "LDRDpost" ||
	     OpName == "LDRBpost" || OpName == "LDRHpost") &&
	    MI.getNumOperands() >= 4 && MI.getOperand(3).isImm()) {
		int wb = ctx.regD(0), rt = ctx.regD(1), base = ctx.regD(2);
		SymVal addr = ctx.getRegVal(st, base);
		SymVal v = (OpName == "LDRXpost") ? st.load(addr)
						  : SymVal{VK_UNKNOWN, 0};
		ctx.setRegVal(st, wb,
			      addSymImm(addr, MI.getOperand(3).getImm()));
		if (rt >= 0)
			ctx.setRegVal(st, rt, v);
		return true;
	}
	if ((OpName == "LDRXpre" || OpName == "LDRWpre" ||
	     OpName == "LDRQpre" || OpName == "LDRDpre") &&
	    MI.getNumOperands() >= 4 && MI.getOperand(3).isImm()) {
		int wb = ctx.regD(0), rt = ctx.regD(1), base = ctx.regD(2);
		SymVal addr = addSymImm(ctx.getRegVal(st, base),
					MI.getOperand(3).getImm());
		ctx.setRegVal(st, wb, addr);
		if (rt >= 0)
			ctx.setRegVal(st, rt,
				      OpName == "LDRXpre"
					  ? st.load(addr)
					  : SymVal{VK_UNKNOWN, 0});
		return true;
	}
	if (OpName == "STRXui" && MI.getNumOperands() >= 3 &&
	    MI.getOperand(2).isImm()) {
		st.store(addSymImm(ctx.getRegVal(st, ctx.regD(1)),
				   MI.getOperand(2).getImm() * 8),
			 ctx.getRegVal(st, ctx.regD(0)));
		return true;
	}
	if (OpName == "STURXi" && MI.getNumOperands() >= 3 &&
	    MI.getOperand(2).isImm()) {
		st.store(addSymImm(ctx.getRegVal(st, ctx.regD(1)),
				   MI.getOperand(2).getImm()),
			 ctx.getRegVal(st, ctx.regD(0)));
		return true;
	}
	if (OpName == "LDRXui" && MI.getNumOperands() >= 3 &&
	    MI.getOperand(2).isImm()) {
		ctx.setRegVal(st, ctx.regD(0),
			      st.load(addSymImm(ctx.getRegVal(st, ctx.regD(1)),
						MI.getOperand(2).getImm() * 8)));
		return true;
	}
	if (OpName == "LDURXi" && MI.getNumOperands() >= 3 &&
	    MI.getOperand(2).isImm()) {
		ctx.setRegVal(st, ctx.regD(0),
			      st.load(addSymImm(ctx.getRegVal(st, ctx.regD(1)),
						MI.getOperand(2).getImm())));
		return true;
	}
	return false;
}

/**
 * stepInstructionRiscv() - Tier-2 symbolic lifter for RISC-V (RV64GC)
 * @st: Abstract register/stack state updated in place.
 * @OpName: LLVM MC opcode name (e.g. "C_ADDI16SP", "C_SDSP", "LUI").
 * @ctx: Disassembled instruction context.
 *
 * Models standard and RVC compressed RISC-V prologue/epilogue sequences.
 *
 * Return: true if @OpName was modeled; false to trigger generic clobbering.
 */
static bool stepInstructionRiscv(AbsState &st, StringRef OpName,
				 const InsnStepCtx &ctx)
{
	const MCInst &MI = ctx.MI;

	if ((OpName == "ADDI" || OpName == "C_ADDI" || OpName == "C_ADDI16SP" ||
	     OpName == "C_ADDI4SPN" || OpName == "ADDIW" ||
	     OpName == "C_ADDIW") &&
	    MI.getNumOperands() >= 3 && MI.getOperand(2).isImm()) {
		int dst = ctx.regD(0), src = ctx.regD(1);
		SymVal v = addSymImm(ctx.getRegVal(st, src),
				     MI.getOperand(2).getImm());
		if ((OpName == "ADDIW" || OpName == "C_ADDIW") &&
		    v.kind == VK_CONST)
			v.off = (int32_t)v.off;
		ctx.setRegVal(st, dst, v);
		return true;
	}
	if ((OpName == "LUI" || OpName == "C_LUI") &&
	    MI.getNumOperands() >= 2 && MI.getOperand(1).isImm()) {
		int dst = ctx.regD(0);
		int32_t s32 = (int32_t)((uint32_t)MI.getOperand(1).getImm() << 12);
		ctx.setRegVal(st, dst, {VK_CONST, (int64_t)s32});
		return true;
	}
	if (OpName == "C_LI" && MI.getNumOperands() >= 2 &&
	    MI.getOperand(1).isImm()) {
		ctx.setRegVal(st, ctx.regD(0),
			      {VK_CONST, MI.getOperand(1).getImm()});
		return true;
	}
	if (OpName == "C_MV" && MI.getNumOperands() >= 2) {
		ctx.setRegVal(st, ctx.regD(0), ctx.getRegVal(st, ctx.regD(1)));
		return true;
	}
	if ((OpName == "ADD" || OpName == "C_ADD" || OpName == "SUB" ||
	     OpName == "C_SUB") &&
	    MI.getNumOperands() >= 3) {
		int dst = ctx.regD(0), s1 = ctx.regD(1), s2 = ctx.regD(2);
		ctx.setRegVal(st, dst,
			      OpName.contains("ADD")
				  ? addSymVals(ctx.getRegVal(st, s1),
					       ctx.getRegVal(st, s2))
				  : subSymVals(ctx.getRegVal(st, s1),
					       ctx.getRegVal(st, s2)));
		return true;
	}
	if (OpName == "ANDI" && ctx.regD(0) == 2 && ctx.regD(1) == 2) {
		st.regs[2] = {VK_ALIGNED_SP, 0};
		return true;
	}
	if ((OpName == "SD" || OpName == "C_SDSP") &&
	    MI.getNumOperands() >= 3 && MI.getOperand(2).isImm()) {
		int src = ctx.regD(0), base = ctx.regD(1);
		st.store(addSymImm(ctx.getRegVal(st, base),
				   MI.getOperand(2).getImm()),
			 ctx.getRegVal(st, src));
		return true;
	}
	if ((OpName == "LD" || OpName == "C_LDSP") &&
	    MI.getNumOperands() >= 3 && MI.getOperand(2).isImm()) {
		int dst = ctx.regD(0), base = ctx.regD(1);
		ctx.setRegVal(st, dst,
			      st.load(addSymImm(ctx.getRegVal(st, base),
						MI.getOperand(2).getImm())));
		return true;
	}
	return false;
}

bool stepInstruction(AbsState &st, const MCInst &MI, StringRef OpName,
		     const MCInstrDesc &Desc, const MCRegisterInfo &MCRI,
		     const ArchSpec &AS, uint64_t NextPC,
		     const MCInstrAnalysis *MIA, uint64_t CurPC,
		     uint64_t InsnSize)
{
	InsnStepCtx ctx{MI, MCRI, AS, MIA, CurPC, NextPC, InsnSize};
	bool handled = false;

	if (AS.llvm_arch == Triple::x86_64)
		handled = stepInstructionX86(st, OpName, Desc, ctx);
	else if (AS.llvm_arch == Triple::aarch64)
		handled = stepInstructionArm64(st, OpName, ctx);
	else if (AS.llvm_arch == Triple::riscv64)
		handled = stepInstructionRiscv(st, OpName, ctx);

	if (!handled)
		clobberGenericDefs(st, MI, Desc, MCRI, AS);
	return handled;
}

/**
 * normalizeRiscvControlFlow() - Classify RISC-V JAL/JALR control-flow roles
 */
void normalizeRiscvControlFlow(const MCInst &MI, StringRef OpName,
			       const MCRegisterInfo &MCRI,
			       bool &is_ret_or_ind_jump, bool &is_uncond_branch,
			       bool &is_call)
{
	int rd = (MI.getNumOperands() >= 1 && MI.getOperand(0).isReg())
		     ? mcRegToDwarf32(MCRI, MI.getOperand(0).getReg(),
				      Triple::riscv64)
		     : -1;
	if (OpName == "JAL") {
		if (rd == 0) {
			is_uncond_branch = true;
			is_call = false;
		} else {
			is_call = true;
		}
	} else if (OpName == "C_J") {
		is_uncond_branch = true;
		is_call = false;
	} else if (OpName == "JALR") {
		if (rd == 0) {
			is_ret_or_ind_jump = true;
			is_call = false;
		} else {
			is_call = true;
		}
	} else if (OpName == "C_JR") {
		is_ret_or_ind_jump = true;
		is_call = false;
	} else if (OpName == "C_JALR") {
		is_call = true;
	}
}
