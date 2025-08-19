# SPDX-License-Identifier: GPL-2.0

# Ensure Kbuild variables are available
include ../scripts/Makefile.include

srctree := $(patsubst %/tools/kexec,%,$(CURDIR))
VMLINUX = $(srctree)/vmlinux
TOOLSDIR := $(srctree)/tools
LIBDIR := $(TOOLSDIR)/lib
BPFDIR := $(LIBDIR)/bpf
ARCH ?= $(shell uname -m | sed -e s/i.86/x86/ -e s/x86_64/x86/ -e s/aarch64.*/arm64/ -e s/riscv64/riscv/ -e s/loongarch.*/loongarch/)
# At present, zboot image format is used by arm64, riscv, loongarch
# And arch/$(ARCH)/boot/vmlinux.bin is the uncompressed file instead of arch/$(ARCH)/boot/Image
ifeq ($(ARCH),$(filter $(ARCH),arm64 riscv loongarch))
	EFI_IMAGE := $(srctree)/arch/$(ARCH)/boot/vmlinuz.efi
	KERNEL_IMAGE := $(srctree)/arch/$(ARCH)/boot/vmlinux.bin
else
	@echo "Unsupported architecture: $(ARCH)"
	@exit 1
endif


CC = clang
CFLAGS = -O2
BPF_PROG_CFLAGS = -g -O2 -target bpf -Wall -I $(BPFDIR) -I .
BPFTOOL = bpftool

# List of generated target files
HEADERS = vmlinux.h bpf_helper_defs.h image_size.h
ZBOOT_TARGETS = bytecode.c zboot_parser_bpf.o bytecode.o


# Targets
zboot: $(HEADERS) $(ZBOOT_TARGETS)

# Rule to generate vmlinux.h from vmlinux
vmlinux.h: $(VMLINUX)
	@command -v $(BPFTOOL) >/dev/null 2>&1 || { echo >&2 "$(BPFTOOL) is required but not found. Please install it."; exit 1; }
	@$(BPFTOOL) btf dump file $(VMLINUX) format c > vmlinux.h

bpf_helper_defs.h: $(srctree)/tools/include/uapi/linux/bpf.h
	@$(QUIET_GEN)$(srctree)/scripts/bpf_doc.py --header \
		--file $(srctree)/tools/include/uapi/linux/bpf.h > bpf_helper_defs.h

image_size.h: $(KERNEL_IMAGE)
	@{ \
		if [ ! -f "$(KERNEL_IMAGE)" ]; then \
			echo "Error: File '$(KERNEL_IMAGE)' does not exist"; \
			exit 1; \
		fi; \
		FILE_SIZE=$$(stat -c '%s' "$(KERNEL_IMAGE)" 2>/dev/null); \
		POWER=4096; \
		while [ $$POWER -le $$FILE_SIZE ]; do \
			POWER=$$((POWER * 2)); \
		done; \
		RINGBUF_SIZE=$$POWER; \
		echo "#define RINGBUF1_SIZE $$RINGBUF_SIZE" > $@; \
		echo "#define IMAGE_SIZE $$FILE_SIZE" >> $@; \
	}


# Rule to generate zboot_parser_bpf.o, depends on vmlinux.h
zboot_parser_bpf.o: zboot_parser_bpf.c vmlinux.h bpf_helper_defs.h
	@$(CC) $(BPF_PROG_CFLAGS) -c zboot_parser_bpf.c -o zboot_parser_bpf.o

# Generate zboot_parser_bpf.lskel.h using bpftool
# Then, extract the opts_data[] and opts_insn[] arrays and remove 'static'
# keywords to avoid being optimized away.
bytecode.c: zboot_parser_bpf.o
	@$(BPFTOOL) gen skeleton -L zboot_parser_bpf.o > zboot_parser_bpf.lskel.h
	@sed -n '/static const char opts_data\[\]/,/;/p' zboot_parser_bpf.lskel.h | sed 's/static const/const/' > $@
	@sed -n '/static const char opts_insn\[\]/,/;/p' zboot_parser_bpf.lskel.h | sed 's/static const/const/' >> $@
	@rm -f zboot_parser_bpf.lskel.h

bytecode.o: bytecode.c
	@$(CC) -c $< -o $@

# Clean up generated files
clean:
	@rm -f $(HEADERS) $(ZBOOT_TARGETS)

.PHONY: all clean
