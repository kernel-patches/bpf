// SPDX-License-Identifier: GPL-2.0-only
/* bpf_scan_ir: optimizer-last LLVM IR analysis for BPF. */

#include "../bpf/fmodret_metadata.h"

#include <algorithm>
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/CaptureTracking.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/Analysis.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#if __has_include("llvm/Plugins/PassPlugin.h")
#include "llvm/Plugins/PassPlugin.h"
#else
#include "llvm/Passes/PassPlugin.h"
#endif
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

namespace {

static constexpr int MaxErrno = 4095;

/* The errors which clean paths of a function return */
using ReturnValues = SmallVector<int64_t, 8>;

/* Return true and set N if V is an errno constant */
static bool errnoConstant(const Value *V, int64_t &N)
{
	auto *C = dyn_cast<ConstantInt>(V);

	if (!C || (C->getBitWidth() != 32 && C->getBitWidth() != 64))
		return false;

	N = C->getSExtValue();
	return N >= -MaxErrno && N < 0;
}

class CleanInstructions {
	DominatorTree &DT;
	DenseMap<const Instruction *, bool> PrivateWrites;

	bool privateDestination(const Value *Pointer, const Instruction &I)
	{
		auto It = PrivateWrites.find(&I);
		if (It != PrivateWrites.end())
			return It->second;
		auto *Allocation = dyn_cast<AllocaInst>(getUnderlyingObject(Pointer));
		bool Private = false;

		if (Allocation && Allocation->getFunction() == I.getFunction()) {
			// A later call may receive the initialized object. Only captures
			// that can precede this write make the write externally visible.
#if LLVM_VERSION_MAJOR >= 21
			Private = !PointerMayBeCapturedBefore(Allocation, true, &I, &DT, true, 256);
#else
			Private = !PointerMayBeCapturedBefore(Allocation, true, true, &I, &DT, true, 256);
#endif
		}
		PrivateWrites[&I] = Private;
		return Private;
	}

public:
	explicit CleanInstructions(DominatorTree &DT) : DT(DT) {}

	bool isClean(const Instruction &I)
	{
		if (auto *Store = dyn_cast<StoreInst>(&I))
			return !Store->isVolatile() && !Store->isAtomic() &&
			       privateDestination(Store->getPointerOperand(), I);
		if (auto *Memory = dyn_cast<MemIntrinsic>(&I))
			return !Memory->isVolatile() &&
			       privateDestination(Memory->getRawDest(), I);
		if (auto *Intrinsic = dyn_cast<IntrinsicInst>(&I)) {
			switch (Intrinsic->getIntrinsicID()) {
			case Intrinsic::assume:
			case Intrinsic::lifetime_start:
			case Intrinsic::lifetime_end:
			case Intrinsic::invariant_start:
			case Intrinsic::invariant_end:
				return true;
			default:
				break;
			}
		}
		return !I.mayHaveSideEffects();
	}
};

static bool cleanBB(BasicBlock *BB, CleanInstructions &Clean)
{
	for (Instruction &I : *BB) {
		if (!Clean.isClean(I))
			return false;
	}
	return true;
}

/* Add the errors which clean paths of F are known to return to VALUES */
static void cleanReturnValues(Function &F, CleanInstructions &Clean, ReturnValues &Values)
{
	SmallPtrSet<BasicBlock *, 32> CleanBBs;
	SmallVector<BasicBlock *, 32> Worklist;
	bool Changed;

	/* The clean blocks which the entry reaches through clean blocks */
	if (cleanBB(&F.getEntryBlock(), Clean)) {
		CleanBBs.insert(&F.getEntryBlock());
		Worklist.push_back(&F.getEntryBlock());
	}
	while (!Worklist.empty()) {
		BasicBlock *BB = Worklist.pop_back_val();

		for (BasicBlock *Successor : successors(BB)) {
			if (!CleanBBs.contains(Successor) && cleanBB(Successor, Clean)) {
				CleanBBs.insert(Successor);
				Worklist.push_back(Successor);
			}
		}
	}

	/*
	 * Keep the blocks which only clean paths reach: after a dirty path joins
	 * a clean one, a branch may depend on what the dirty path did
	 */
	do {
		Changed = false;
		for (BasicBlock &BB : F) {
			if (!CleanBBs.contains(&BB))
				continue;
			for (BasicBlock *Pred : predecessors(&BB)) {
				if (!CleanBBs.contains(Pred)) {
					CleanBBs.erase(&BB);
					Changed = true;
					break;
				}
			}
		}
	} while (Changed);

	/*
	 * The returns of the clean blocks which only clean paths reach or which
	 * one of them branches to. Dirty paths may also reach the latter, but
	 * the returned constant is the same on all paths.
	 */
	for (BasicBlock &BB : F) {
		auto *Return = dyn_cast<ReturnInst>(BB.getTerminator());
		bool Entered = CleanBBs.contains(&BB);
		int64_t N;

		if (!Return || !Return->getReturnValue() || !cleanBB(&BB, Clean))
			continue;
		for (BasicBlock *Pred : predecessors(&BB))
			Entered |= CleanBBs.contains(Pred);
		if (!Entered)
			continue;
		if (errnoConstant(Return->getReturnValue(), N))
			Values.push_back(N);
	}
	llvm::sort(Values);
	Values.erase(std::unique(Values.begin(), Values.end()), Values.end());
}

struct FunctionDescription {
	Function *Fn;
	unsigned Flags;
	ReturnValues Values;
};

static void emitDescriptions(Module &M, ArrayRef<FunctionDescription> Functions)
{
	auto *I32 = Type::getInt32Ty(M.getContext());
	auto *I64 = Type::getInt64Ty(M.getContext());
	unsigned PtrSize = M.getDataLayout().getPointerSize();
	auto N = [&](unsigned V) -> Constant * { return ConstantInt::get(I32, V); };

	for (const auto &F : Functions) {
		unsigned Size = FMODRET_META_HEADER_SIZE(PtrSize) +
				F.Values.size() * FMODRET_META_VALUE_SIZE;
		SmallVector<Constant *, 16> Fields = {
			N(FMODRET_META_MAGIC), N(FMODRET_META_VERSION), N(Size), N(F.Flags),
			F.Fn, N(F.Values.size()), N(0),
		};

		for (int64_t V : F.Values)
			Fields.push_back(ConstantInt::getSigned(I64, V));
		Constant *Record = ConstantStruct::getAnon(M.getContext(), Fields, true);
		auto *GV = new GlobalVariable(M, Record->getType(), true, GlobalValue::PrivateLinkage,
					      Record, "fmodret.function." + F.Fn->getName());
		GV->setSection(".BTF_fmodret_candidates");
		GV->setAlignment(M.getDataLayout().getPointerABIAlignment(0));
		appendToUsed(M, {GV});
	}
}

#if LLVM_VERSION_MAJOR >= 24
class BpfScanIRPass : public RequiredPassInfoMixin<BpfScanIRPass>
#else
class BpfScanIRPass : public PassInfoMixin<BpfScanIRPass>
#endif
{
public:
	PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM)
	{
		// Avoid emitting duplicate descriptions if bpf_scan_ir runs again
		// on the same module.
		if (M.getNamedMetadata("bpf_scan_ir.done"))
			return PreservedAnalyses::all();

		SmallVector<FunctionDescription, 32> Descriptions;
		auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();

		for (Function &F : M) {
			if (F.isIntrinsic() || F.isDeclaration() || F.hasAvailableExternallyLinkage())
				continue;
			Type *Ret = F.getReturnType();
			unsigned Flags = 0;
			ReturnValues Values;

			if (!Ret->isIntegerTy(32) && !Ret->isIntegerTy(64))
				continue;
			if (F.isWeakForLinker())
				Flags |= FMODRET_FN_WEAK;
			if (Ret->isIntegerTy(64))
				Flags |= FMODRET_FN_RET64;
			auto &DT = FAM.getResult<DominatorTreeAnalysis>(F);
			CleanInstructions Clean(DT);

			cleanReturnValues(F, Clean, Values);
			/* A weak definition always has a record, see fmodret_metadata.h */
			if (!Values.empty() || (Flags & FMODRET_FN_WEAK))
				Descriptions.push_back({&F, Flags, std::move(Values)});
		}
		if (Descriptions.empty())
			return PreservedAnalyses::all();
		emitDescriptions(M, Descriptions);
		M.getOrInsertNamedMetadata("bpf_scan_ir.done");

		PreservedAnalyses PA;
		PA.preserve<FunctionAnalysisManagerModuleProxy>();
		PA.preserveSet<CFGAnalyses>();
		return PA;
	}

	static bool isRequired() { return true; }
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo()
{
	return {
		LLVM_PLUGIN_API_VERSION,
		"bpf_scan_ir",
		"1.0",
		[](PassBuilder &PB) {
			PB.registerOptimizerLastEPCallback(
				[](ModulePassManager &MPM, OptimizationLevel, auto...) {
					MPM.addPass(BpfScanIRPass());
				   }
			);
		}
	};
}
