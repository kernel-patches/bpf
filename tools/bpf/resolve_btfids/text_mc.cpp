// SPDX-License-Identifier: GPL-2.0-only
/*
 * The instructions of any arch in the terms of text_insn.h, on top of LLVM's MC
 * layer. Nothing in this file depends on the arch: see text_mc.h for the rest.
 *
 *	length, MCInst			MCDisassembler::getInstruction()
 *	branch, call			MCInstrAnalysis, which asks MCInstrDesc
 *	target				MCInstrAnalysis::evaluateBranch()
 *	registers written		MCInstrDesc: defs, implicit defs
 *	registers read			MCInstrDesc: the other operands, implicit uses
 *	load				MCInstrDesc::mayLoad()
 *	eax and rax, w0 and x0		MCRegAliasIterator
 *
 * Whatever MC does not describe completely writes TEXT_ALL_REGS.
 */

#include <llvm/Config/llvm-config.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstrAnalysis.h>
#include <llvm/MC/MCInstrDesc.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/MCTargetOptions.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Support/Format.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>

#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

extern "C" {
#include "text_mc.h"
}

#if LLVM_VERSION_MAJOR < 17
#error "LLVM 17, the oldest one which can build the kernel, or later"
#endif

using namespace llvm;

namespace {

enum { NO_REG = 0xff, ZERO_REG = 0xfe };

/* An LLVM register in the terms of text_insn.h */
struct Reg {
	u32 mask = 0;		/* the registers which it overlaps */
	u8 nr = NO_REG;		/* the register if it overlaps one, or ZERO_REG */
	u8 bits = 0;		/* 64: all of it, 32: the low half, a write zero extends, 0: some part */
};

/* What is known about an opcode before its operands are */
struct Opcode {
	u32 implicit_defs = 0;
	u32 implicit_uses = 0;
	unsigned int implicit_def = 0, implicit_use = 0;	/* the first ones, LLVM registers */
	bool unmodeled = false, is_return = false;
	std::vector<const mc_pattern *> patterns;
};

struct Decoder {
	std::unique_ptr<MCRegisterInfo> MRI;
	std::unique_ptr<MCAsmInfo> MAI;
	std::unique_ptr<MCInstrInfo> MII;
	std::unique_ptr<MCSubtargetInfo> STI;
	std::unique_ptr<MCContext> Ctx;
	std::unique_ptr<MCDisassembler> Dis;
	std::unique_ptr<MCInstrAnalysis> MIA;
	std::vector<Reg> regs;
	std::vector<Opcode> opcodes;
	MCInst inst;
};

Decoder d;

/* MC_TARGET is LLVM's name of the arch, see llvm-mc.sh */
#define INITIALIZE_(target, what)	LLVMInitialize##target##what()
#define INITIALIZE(target, what)	INITIALIZE_(target, what)

raw_ostream &error()
{
	return errs() << "text_mc: LLVM " LLVM_VERSION_STRING ": ";
}

bool create()
{
	MCTargetOptions options;
	std::string message;
#if LLVM_VERSION_MAJOR >= 22
	Triple triple(mc_arch.triple);
#else
	const char *triple = mc_arch.triple;
#endif
	const Target *target;

	INITIALIZE(MC_TARGET, TargetInfo);
	INITIALIZE(MC_TARGET, TargetMC);
	INITIALIZE(MC_TARGET, Disassembler);
	target = TargetRegistry::lookupTarget(triple, message);
	if (!target) {
		error() << message << "\n";
		return false;
	}
	d.MRI.reset(target->createMCRegInfo(triple));
	d.MAI.reset(target->createMCAsmInfo(*d.MRI, triple, options));
	d.MII.reset(target->createMCInstrInfo());
	d.STI.reset(target->createMCSubtargetInfo(triple, "", mc_arch.features));
#if LLVM_VERSION_MAJOR >= 23
	d.Ctx.reset(new MCContext(triple, *d.MAI, *d.MRI, *d.STI));
#else
	d.Ctx.reset(new MCContext(Triple(mc_arch.triple), d.MAI.get(), d.MRI.get(), d.STI.get()));
#endif
	d.Dis.reset(target->createMCDisassembler(*d.STI, *d.Ctx));
	d.MIA.reset(target->createMCInstrAnalysis(d.MII.get()));
	return d.Dis && d.MIA;
}

/* Call FN(LLVM register, index) for each of the NAMES */
template <typename Fn> bool for_each_reg(const char *names, Fn fn)
{
	std::istringstream in(names ?: "");
	std::string name;
	bool ok = true;

	for (unsigned int i = 0, r; in >> name; i++) {
		for (r = 1; r < d.MRI->getNumRegs() && name != d.MRI->getName(r); r++)
			;
		if (r < d.MRI->getNumRegs()) {
			fn(r, i);
			continue;
		}
		error() << "no register " << name << "\n";
		ok = false;
	}
	return ok;
}

bool read_regs()
{
	bool ok;

	d.regs.resize(d.MRI->getNumRegs());
	ok = for_each_reg(mc_arch.regs, [&](unsigned int r, unsigned int nr) {
		for (MCRegAliasIterator alias(r, d.MRI.get(), true); alias.isValid(); ++alias) {
			Reg &reg = d.regs[*alias];

			/* The iterator may come to a register more than once */
			reg.mask |= 1U << nr;
			reg.nr = reg.mask == 1U << nr ? nr : NO_REG;
			reg.bits = *alias == r ? 64 : 0;
		}
	});
	ok &= for_each_reg(mc_arch.regs32, [&](unsigned int r, unsigned int) { d.regs[r].bits = 32; });
	ok &= for_each_reg(mc_arch.zero_regs, [&](unsigned int r, unsigned int) { d.regs[r].nr = ZERO_REG; });
	return ok;
}

bool read_opcodes()
{
	std::unordered_map<std::string_view, Opcode *> by_name;
	bool ok = true;

	d.opcodes.resize(d.MII->getNumOpcodes());
	by_name.reserve(d.opcodes.size());
	for (unsigned int op = 0; op < d.opcodes.size(); op++) {
		const MCInstrDesc &desc = d.MII->get(op);
		Opcode &o = d.opcodes[op];

		by_name[d.MII->getName(op)] = &o;
		for (MCPhysReg r : desc.implicit_defs()) {
			o.implicit_defs |= d.regs[r].mask;
			if (!o.implicit_def && d.regs[r].mask)
				o.implicit_def = r;
		}
		for (MCPhysReg r : desc.implicit_uses())
			if (!o.implicit_use && d.regs[r].mask)
				o.implicit_use = r;
		for (MCPhysReg r : desc.implicit_uses())
			o.implicit_uses |= d.regs[r].mask;
		/* defs_of() does not look for the last two */
		o.unmodeled = desc.hasUnmodeledSideEffects() || desc.hasOptionalDef() ||
			      desc.variadicOpsAreDefs();
	}
	for (const mc_pattern *pattern = mc_arch.patterns; pattern->opcode; pattern++) {
		auto it = by_name.find(pattern->opcode);

		if (it == by_name.end()) {
			error() << "no opcode " << pattern->opcode << "\n";
			ok = false;
		} else if (pattern->kind == TEXT_RETURN) {
			it->second->is_return = true;
		} else if (pattern->kind != TEXT_OTHER) {
			it->second->patterns.push_back(pattern);
		} else {
			it->second->unmodeled = false;
			it->second->implicit_defs |= pattern->defs;
		}
	}
	return ok;
}

const Reg &reg_of(const MCInst &inst, const Opcode &o, u8 nr, bool def)
{
	static const Reg none;

	if (nr == MC_IMPLICIT)
		return d.regs[def ? o.implicit_def : o.implicit_use];
	if (nr >= inst.getNumOperands() || !inst.getOperand(nr).isReg())
		return none;
	return d.regs[inst.getOperand(nr).getReg()];
}

bool holds(const MCInst &inst, const mc_predicate &p)
{
	const MCOperand *a, *b;

	if (p.kind == MC_TRUE)
		return true;
	if (p.a >= inst.getNumOperands())
		return false;
	a = &inst.getOperand(p.a);
	switch (p.kind) {
	case MC_ZERO_REG:
		return a->isReg() && d.regs[a->getReg()].nr == ZERO_REG;
	case MC_SAME_REG:
		if ((unsigned int)p.b >= inst.getNumOperands())
			return false;
		b = &inst.getOperand(p.b);
		return a->isReg() && b->isReg() && a->getReg() == b->getReg();
	case MC_IMM:
		return a->isImm() && a->getImm() == p.b;
	}
	return false;
}

/* Describe INST as PATTERN says. Return false, and leave TI alone, if it does not match */
bool match(const MCInst &inst, const Opcode &o, const mc_pattern &pattern, text_insn *ti)
{
	const Reg &dst = reg_of(inst, o, pattern.dst, true);
	u8 kind = pattern.kind, src = 0, src2 = 0;
	bool is32 = dst.bits == 32;
	u64 imm = pattern.value;

	if (!holds(inst, pattern.predicates[0]) || !holds(inst, pattern.predicates[1]))
		return false;
	if (dst.nr >= TEXT_MAX_REGS || !dst.bits)
		return false;
	if (kind != TEXT_MOV && kind != TEXT_SEXT32 && kind != TEXT_SELECT) {
		if (!pattern.fixed) {
			if (pattern.imm >= inst.getNumOperands() || !inst.getOperand(pattern.imm).isImm())
				return false;
			imm = inst.getOperand(pattern.imm).getImm();
		}
		if (pattern.shift >= inst.getNumOperands())
			return false;
		if (pattern.shift)
			imm <<= inst.getOperand(pattern.shift).getImm();
		if (pattern.invert)
			imm = ~imm;
		if (is32)
			imm = (u32)imm;
	}
	if (kind != TEXT_MOV_IMM) {
		src = src2 = reg_of(inst, o, pattern.src, false).nr;
		if (kind == TEXT_SELECT)
			src2 = reg_of(inst, o, pattern.src2, false).nr;
		/* The zero register is a constant which is not an error: only the other source counts */
		if (src == ZERO_REG)
			src = src2;
		if (src2 == ZERO_REG)
			src2 = src;
		if (src >= TEXT_MAX_REGS || src2 >= TEXT_MAX_REGS)
			return false;
	}
	ti->kind = kind;
	ti->is32 = is32;
	ti->dst = dst.nr;
	ti->src = src;
	ti->src2 = src2;
	ti->op = pattern.op;
	ti->imm = imm;
	ti->imm2 = pattern.or_zero ? 0 : imm;
	return true;
}

void control_flow(const MCInst &inst, const Opcode &o, u64 addr, text_insn *ti)
{
	const MCInstrDesc &desc = d.MII->get(inst.getOpcode());
	const MCInstrAnalysis &MIA = *d.MIA;
	u64 target;

	if (o.is_return)
		ti->kind = TEXT_RETURN;
	else if (MIA.isCall(inst))
		ti->kind = TEXT_CALL;
	else if (MIA.isUnconditionalBranch(inst) || (MIA.isIndirectBranch(inst) && desc.isBarrier()))
		ti->kind = TEXT_BRANCH;
	else if (MIA.isBranch(inst))
		ti->kind = TEXT_COND_BRANCH;
	if (ti->kind >= TEXT_BRANCH && MIA.evaluateBranch(inst, addr, ti->len, target))
		ti->imm = target;
	if (ti->kind == TEXT_BRANCH || ti->kind == TEXT_RETURN)
		ti->defs = 0;
}

/* Return the registers which INST writes */
u32 defs_of(const MCInst &inst, const Opcode &o)
{
	const MCInstrDesc &desc = d.MII->get(inst.getOpcode());
	u32 defs = o.implicit_defs;

	if (o.unmodeled)
		return TEXT_ALL_REGS;
	/* The operands are not those of the description: which ones are the defs? */
	if (desc.getNumDefs() && inst.getNumOperands() < desc.getNumOperands())
		return TEXT_ALL_REGS;
	for (unsigned int i = 0; i < desc.getNumDefs(); i++) {
		if (!inst.getOperand(i).isReg())
			return TEXT_ALL_REGS;
		defs |= d.regs[inst.getOperand(i).getReg()].mask;
	}
	return defs;
}

/* Return the registers which INST reads */
u32 uses_of(const MCInst &inst, const Opcode &o)
{
	u32 uses = o.implicit_uses;

	if (o.unmodeled)
		return TEXT_ALL_REGS;
	for (unsigned int i = d.MII->get(inst.getOpcode()).getNumDefs(); i < inst.getNumOperands(); i++)
		if (inst.getOperand(i).isReg())
			uses |= d.regs[inst.getOperand(i).getReg()].mask;
	return uses;
}

int decode(const void *code, unsigned int len, u64 addr, text_insn *ti)
{
	MCInst &inst = d.inst;
	uint64_t size = 0;

	inst = MCInst();
	*ti = text_insn{};
	/* After SoftFail the MCInst is valid: LLVM has it for "ldtr w8, [x8]" */
	if (d.Dis->getInstruction(inst, size, ArrayRef<uint8_t>((const uint8_t *)code, len), addr,
				  nulls()) == MCDisassembler::Fail)
		return -1;
	ti->len = size;

	const Opcode &o = d.opcodes[inst.getOpcode()];

	ti->defs = defs_of(inst, o);
	ti->uses = uses_of(inst, o);
	ti->load = d.MII->get(inst.getOpcode()).mayLoad();
	for (const mc_pattern *pattern : o.patterns) {
		if (match(inst, o, *pattern, ti)) {
			ti->defs &= ~(1U << ti->dst);
			return 0;
		}
	}
	control_flow(inst, o, addr, ti);
	return 0;
}

void print(raw_ostream &os, const text_insn &ti)
{
	os << "kind " << (int)ti.kind << " is32 " << ti.is32 << " dst " << (int)ti.dst
	   << " src " << (int)ti.src << " src2 " << (int)ti.src2
	   << " op " << (int)ti.op
	   << " defs " << format_hex(ti.defs, 1) << " imm " << format_hex(ti.imm, 1)
	   << " imm2 " << format_hex(ti.imm2, 1);
	os << " uses " << format_hex(ti.uses, 1) << " load " << ti.load;
}

bool run_tests()
{
	bool ok = true;

	for (const mc_test *test = mc_arch.tests; test->code; test++) {
		const text_insn &want = test->insn;
		std::istringstream in(test->code);
		std::vector<uint8_t> code;
		unsigned int byte;
		text_insn ti;

		while (in >> std::hex >> byte)
			code.push_back(byte);
		if (!decode(code.data(), code.size(), MC_TEST_ADDR, &ti) && ti.len == code.size() &&
		    ti.kind == want.kind && ti.is32 == want.is32 && ti.dst == want.dst &&
		    ti.src == want.src && ti.src2 == want.src2 &&
		    ti.op == want.op &&
		    (!want.uses || (ti.uses == want.uses && ti.load == want.load)) &&
		    ti.defs == want.defs && ti.imm == want.imm && ti.imm2 == want.imm2)
			continue;
		print(error() << test->code << " is " << d.MII->getName(d.inst.getOpcode()) << ", length "
			      << (int)ti.len << ", ", ti);
		print(errs() << "\n\texpected: ", want);
		errs() << "\n";
		ok = false;
	}
	return ok;
}

} /* namespace */

extern "C" const struct text_arch *text_arch_init(unsigned int machine)
{
	static text_arch arch = mc_arch.arch;

	if (machine != mc_arch.machine) {
		errs() << "text_mc: built for " << mc_arch.triple << ", not for ELF machine " << machine << "\n";
		return nullptr;
	}
	if (!create() || !read_regs() || !read_opcodes() || !run_tests()) {
		error() << "the table of the arch does not fit it. Set LLVM_CONFIG to the "
			   "llvm-config of another LLVM, or switch CONFIG_BPF_FMODRET_SCAN off\n";
		return nullptr;
	}
	arch.decode = decode;
	return &arch;
}
