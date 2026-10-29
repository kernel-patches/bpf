/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
#ifndef __BPFTOOL_LLVM_DISASM_H
#define __BPFTOOL_LLVM_DISASM_H

#include <stddef.h>
#include <stdint.h>

/*
 * Interface between bpftool and its libLLVM-based JIT disassembler.
 *
 * The disassembler is usually built as a plugin, bpftool-llvm.so, that
 * bpftool loads with dlopen(); bpftool then looks up the
 * BPFTOOL_LLVM_OPS_SYM symbol in it. The plugin can come from a different
 * build than the bpftool binary, so bump BPFTOOL_LLVM_ABI_VERSION on any
 * incompatible change to struct bpftool_llvm_ops, and always keep
 * abi_version as its first member.
 */
#define BPFTOOL_LLVM_ABI_VERSION	1U
#define BPFTOOL_LLVM_OPS_SYM		"bpftool_llvm_ops"

struct bpftool_llvm_ops {
	unsigned int abi_version;
	/* Initialize libLLVM targets and disassemblers. Returns 0 on success. */
	int (*init)(void);
	/*
	 * Create a disassembler context for @arch, or for the host if @arch
	 * is NULL. Returns NULL on failure.
	 */
	void *(*create_context)(const char *arch);
	void (*destroy_context)(void *ctx);
	/*
	 * Disassemble the instruction at @bytes, located at address @pc, into
	 * @buf. Returns the size of the instruction, or 0 if it is invalid.
	 */
	size_t (*disassemble)(void *ctx, uint8_t *bytes, uint64_t size,
			      uint64_t pc, char *buf, size_t buf_size);
};

extern const struct bpftool_llvm_ops bpftool_llvm_ops;

#endif /* __BPFTOOL_LLVM_DISASM_H */
