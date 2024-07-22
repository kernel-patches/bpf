// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <test_progs.h>

#ifdef HAVE_LLVM_SUPPORT

#include <llvm-c/Core.h>
#include <llvm-c/Disassembler.h>
#include <llvm-c/Target.h>
#include <llvm-c/TargetMachine.h>

static bool llvm_initialized;

/* This callback to set the ref_type is necessary to have the LLVM disassembler
 * print PC-relative addresses instead of byte offsets for branch instruction
 * targets.
 */
static const char *
symbol_lookup_callback(__maybe_unused void *disasm_info,
		       __maybe_unused uint64_t ref_value,
		       uint64_t *ref_type, __maybe_unused uint64_t ref_PC,
		       __maybe_unused const char **ref_name)
{
	*ref_type = LLVMDisassembler_ReferenceType_InOut_None;
	return NULL;
}

int get_jited_program_text(int fd, char *text, size_t text_sz)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	LLVMDisasmContextRef ctx = NULL;
	FILE *text_out = NULL;
	uint8_t *image = NULL;
	char *triple = NULL;
	__u32 len, pc, cnt;
	char buf[256];
	int i, err = 0;

	if (!llvm_initialized) {
		LLVMInitializeAllTargetInfos();
		LLVMInitializeAllTargetMCs();
		LLVMInitializeAllDisassemblers();
		llvm_initialized = 1;
	}

	text_out = fmemopen(text, text_sz, "w");
	if (!ASSERT_OK_PTR(text_out, "open_memstream")) {
		err = -errno;
		goto out;
	}

	/* first call is to find out jited program len */
	err = bpf_prog_get_info_by_fd(fd, &info, &info_len);
	if (!ASSERT_OK(err, "bpf_prog_get_info_by_fd #1"))
		goto out;

	len = info.jited_prog_len;
	image = malloc(len);
	if (!ASSERT_OK_PTR(image, "malloc(info.jited_prog_len)")) {
		err = -ENOMEM;
		goto out;
	}

	memset(&info, 0, sizeof(info));
	info.jited_prog_insns = (__u64)image;
	info.jited_prog_len = len;
	err = bpf_prog_get_info_by_fd(fd, &info, &info_len);
	if (!ASSERT_OK(err, "bpf_prog_get_info_by_fd #2"))
		goto out;

	triple = LLVMGetDefaultTargetTriple();
	ctx = LLVMCreateDisasm(triple, NULL, 0, NULL, symbol_lookup_callback);
	if (!ASSERT_OK_PTR(ctx, "LLVMCreateDisasm")) {
		err = -EINVAL;
		goto out;
	}

	cnt = LLVMSetDisasmOptions(ctx, LLVMDisassembler_Option_PrintImmHex);
	if (!ASSERT_EQ(cnt, 1, "LLVMSetDisasmOptions")) {
		err = -EINVAL;
		goto out;
	}

	pc = 0;
	while (pc < len) {
		cnt = LLVMDisasmInstruction(ctx, image + pc, len - pc, pc,
					    buf, sizeof(buf));
		if (cnt == 0) {
			PRINT_FAIL("Can't disasm instruction at offset %d:", pc);
			for (i = 0; i < 16 && pc + i < len; ++i)
				PRINT_FAIL(" %02x", image[pc + i]);
			PRINT_FAIL("\n");
			goto out;
		}
		fprintf(text_out, "%4x:%s\n", pc, buf);
		pc += cnt;
	}
out:
	if (text_out)
		fclose(text_out);
	if (image)
		free(image);
	if (triple)
		LLVMDisposeMessage(triple);
	if (ctx)
		LLVMDisasmDispose(ctx);
	return err;
}

#else /* HAVE_LLVM_SUPPORT */

int get_jited_program_text(int fd, char *text, size_t text_sz)
{
	if (env.verbosity >= VERBOSE_VERY)
		printf("compiled w/o llvm development libraries, can't dis-assembly binary code");
	return -ENOTSUP;
}

#endif /* HAVE_LLVM_SUPPORT */
