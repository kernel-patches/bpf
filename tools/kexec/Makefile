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
BPF_PROG_CFLAGS = -g -fno-merge-all-constants -O2 -target bpf -Wall -I $(BPFDIR) -I .
BPFTOOL = bpftool

# ---------------------------------------------------------------------------
# Shared generated headers (common to all targets)
# ---------------------------------------------------------------------------
HEADERS = vmlinux.h bpf_helper_defs.h image_size.h

# ---------------------------------------------------------------------------
# Per-target artifact lists
# To add a new target (e.g. uki), append to BPF_TARGETS and define a
# <name>: phony rule below.  All build rules are driven by pattern rules
# and require no further changes.
#
# Artifacts produced per prefix <P>:
#   <P>_parser_bpf.o       - compiled BPF object
#   <P>_parser_bpf.lskel.h - light skeleton header
#   <P>_bytecode.c         - extracted opts_data / opts_insn arrays
#   <P>_bytecode.o         - compiled bytecode object
#   <P>.bpf                - final ELF wrapper with .bpf.1 section
# ---------------------------------------------------------------------------
BPF_TARGETS = zboot

define BPF_ARTIFACTS
$(1)_parser_bpf.o $(1)_parser_bpf.lskel.h $(1)_bytecode.c $(1)_bytecode.o $(1).bpf
endef

ALL_BPF_ARTIFACTS = $(foreach t,$(BPF_TARGETS),$(call BPF_ARTIFACTS,$(t)))

# ---------------------------------------------------------------------------
# Top-level phony targets
# ---------------------------------------------------------------------------
zboot: $(HEADERS) $(call BPF_ARTIFACTS,zboot) build_zboot_image

.PHONY: zboot clean

# ---------------------------------------------------------------------------
# Shared header rules
# ---------------------------------------------------------------------------

# Rule to generate vmlinux.h from vmlinux
vmlinux.h: $(VMLINUX)
	@command -v $(BPFTOOL) >/dev/null 2>&1 || { echo >&2 "$(BPFTOOL) is required but not found. Please install it."; exit 1; }
	@$(BPFTOOL) btf dump file $(VMLINUX) format c > vmlinux.h

bpf_helper_defs.h: $(srctree)/tools/include/uapi/linux/bpf.h
	@$(QUIET_GEN)$(srctree)/scripts/bpf_doc.py --header \
		--file $(srctree)/tools/include/uapi/linux/bpf.h > bpf_helper_defs.h

# Default estimated size for initramfs (can be overridden by user)
INITRD_ESTIMATE_SIZE ?= 67108864   # 64MB

# In worst case, this image includes vmlinuz.efi, initramfs and cmdline
image_size.h: $(KERNEL_IMAGE)
	@{ \
		if [ ! -f "$(KERNEL_IMAGE)" ]; then \
			echo "Error: File '$(KERNEL_IMAGE)' does not exist"; \
			exit 1; \
		fi; \
		KERNEL_SIZE=$$(stat -c '%s' "$(KERNEL_IMAGE)" 2>/dev/null); \
		ELF_OVERHEAD=4096; \
		TOTAL_SIZE=$$((KERNEL_SIZE + $(INITRD_ESTIMATE_SIZE) + ELF_OVERHEAD)); \
		POWER=4096; \
		while [ $$POWER -le $$TOTAL_SIZE ]; do \
			POWER=$$((POWER * 2)); \
		done; \
		RINGBUF_SIZE=$$POWER; \
		echo "#define IMAGE_SIZE_POWER2_ALIGN $$RINGBUF_SIZE" > $@; \
		echo "#define IMAGE_SIZE $$TOTAL_SIZE" >> $@; \
		echo "#define KERNEL_SIZE $$KERNEL_SIZE" >> $@; \
		echo "#define INITRD_SIZE $(INITRD_ESTIMATE_SIZE)" >> $@; \
	}

# ---------------------------------------------------------------------------
# Pattern rules: BPF build pipeline
# All rules below are prefix-agnostic; % matches zboot, uki, etc.
# ---------------------------------------------------------------------------

%_parser_bpf.o: %_parser_bpf.c vmlinux.h bpf_helper_defs.h
	@$(CC) $(BPF_PROG_CFLAGS) -c $< -o $@

%_parser_bpf.lskel.h: %_parser_bpf.o
	@$(BPFTOOL) gen skeleton -L $< > $@

# Extract opts_data[] and opts_insn[] arrays from the skeleton header,
# stripping 'static' so the symbols are not optimized away by the compiler.
# This rule is intentionally generic: all parsers expose the same symbol names.
%_bytecode.c: %_parser_bpf.lskel.h
	@sed -n '/static const char opts_data\[\]/,/;/p' $< | sed 's/static const/const/' > $@
	@sed -n '/static const char opts_insn\[\]/,/;/p' $< | sed 's/static const/const/' >> $@

%_bytecode.o: %_bytecode.c
	@$(CC) $(CFLAGS) -c $< -o $@


# Wrap the bytecode ELF object into a new ELF container as section .bpf.1
# ---------------------------------------------------------------------------
# Per-target BPF section definitions
# Format: space-separated "sectionname:sourcefile" pairs
# ---------------------------------------------------------------------------
ZBOOT_BPF_MAPS := .bpf.1:zboot_bytecode.o

# ---------------------------------------------------------------------------
# Helpers to build objcopy flags from a BPF_MAPS list
# ---------------------------------------------------------------------------
section_name       = $(firstword $(subst :, ,$(1)))
source_file        = $(lastword  $(subst :, ,$(1)))

only_section_flags = $(foreach m,$(1),--only-section=$(call section_name,$(m)))

# ---------------------------------------------------------------------------
# Template: generates the %.bpf rule for a given target
# $(1) = lowercase target name, e.g. zboot
# $(2) = UPPER prefix for _BPF_MAPS variable, e.g. ZBOOT
#
# Sections are added one at a time in the order defined in $(2)_BPF_MAPS.
# objcopy does not guarantee section order when all --add-section flags are
# given in a single invocation, so we chain N calls through a .work.o file
# to preserve the declared order.
# ---------------------------------------------------------------------------
define BPF_WRAPPER_RULE
$(1).bpf: $(foreach m,$($(2)_BPF_MAPS),$(call source_file,$(m)))
	@echo '' | $(CC) -x c - -c -o $$@.work.o
	$(foreach m,$($(2)_BPF_MAPS),\
	@objcopy --add-section $(call section_name,$(m))=$(call source_file,$(m)) \
	         --set-section-flags $(call section_name,$(m))=readonly,data \
	         $$@.work.o $$@.next.o && mv $$@.next.o $$@.work.o
	)
	@objcopy $(call only_section_flags,$($(2)_BPF_MAPS)) $$@.work.o $$@
	@rm -f $$@.work.o
endef

$(eval $(call BPF_WRAPPER_RULE,zboot,ZBOOT))

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------
clean:
	@rm -f $(HEADERS) $(ALL_BPF_ARTIFACTS) *.base.o
