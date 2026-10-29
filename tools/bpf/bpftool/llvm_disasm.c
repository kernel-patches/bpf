// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * libLLVM-based disassembler for JITed programs.
 *
 * This file is usually built as bpftool-llvm.so, the only bpftool component
 * linked against libLLVM, which bpftool loads only when it needs to
 * disassemble JITed programs (see jit_disasm.c). It is linked into bpftool
 * directly when libLLVM is a static library.
 */
#include <string.h>

#include <llvm-c/Core.h>
#include <llvm-c/Disassembler.h>
#include <llvm-c/Target.h>
#include <llvm-c/TargetMachine.h>

#include "llvm_disasm.h"

/*
 * This callback to set the ref_type is necessary to have the LLVM disassembler
 * print PC-relative addresses instead of byte offsets for branch instruction
 * targets.
 */
static const char *
symbol_lookup_callback(void *disasm_info, uint64_t ref_value,
		       uint64_t *ref_type, uint64_t ref_PC,
		       const char **ref_name)
{
	*ref_type = LLVMDisassembler_ReferenceType_InOut_None;
	return NULL;
}

static int llvm_init(void)
{
	LLVMInitializeAllTargetInfos();
	LLVMInitializeAllTargetMCs();
	LLVMInitializeAllDisassemblers();
	return 0;
}

static void *llvm_create_context(const char *arch)
{
	LLVMDisasmContextRef ctx;
	char *triple;

	if (arch)
		triple = LLVMNormalizeTargetTriple(arch);
	else
		triple = LLVMGetDefaultTargetTriple();
	if (!triple)
		return NULL;

	/*
	 * Enable all aarch64 ISA extensions so the disassembler can handle any
	 * instruction the kernel JIT might emit (e.g. ARM64 LSE atomics).
	 */
	if (!strncmp(triple, "aarch64", 7))
		ctx = LLVMCreateDisasmCPUFeatures(triple, "", "+all", NULL, 0, NULL,
						  symbol_lookup_callback);
	else
		ctx = LLVMCreateDisasm(triple, NULL, 0, NULL, symbol_lookup_callback);
	LLVMDisposeMessage(triple);

	return ctx;
}

static void llvm_destroy_context(void *ctx)
{
	LLVMDisasmDispose(ctx);
}

static size_t llvm_disassemble(void *ctx, uint8_t *bytes, uint64_t size,
			       uint64_t pc, char *buf, size_t buf_size)
{
	return LLVMDisasmInstruction(ctx, bytes, size, pc, buf, buf_size);
}

const struct bpftool_llvm_ops bpftool_llvm_ops = {
	.abi_version		= BPFTOOL_LLVM_ABI_VERSION,
	.init			= llvm_init,
	.create_context		= llvm_create_context,
	.destroy_context	= llvm_destroy_context,
	.disassemble		= llvm_disassemble,
};
