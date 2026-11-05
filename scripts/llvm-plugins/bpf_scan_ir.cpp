// SPDX-License-Identifier: GPL-2.0-only
/* bpf_scan_ir: optimizer-last LLVM IR analysis for BPF. */

#include "../bpf/fmodret_metadata.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/Analysis.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
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

/* The errors which clean paths of a function return */
using ReturnValues = SmallVector<int64_t, 8>;

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
			/*
			 * Nothing finds the values yet. A weak definition always
			 * has a record, see fmodret_metadata.h.
			 */
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
