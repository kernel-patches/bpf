# SPDX-License-Identifier: GPL-2.0
#
# Shared fragment for selftests that compile *.bpf.c into BPF objects +
# skeletons and link them into userspace test binaries, without each
# subsystem's Makefile re-implementing the libbpf/bpftool/vmlinux.h machinery.
#
# Caller contract (per-test Makefile):
#
#     BPF_SRCS         := foo.bpf.c bar.bpf.c
#     TEST_GEN_PROGS   := foo_test
#     OVERRIDE_TARGETS := 1              # MUST be set before lib.mk
#     include ../lib.mk                  # defines OUTPUT, CC, Q, msg,
#     include ../lib.bpf.mk              #   selfdir, top_srcdir; honours OVERRIDE
#
#     $(OUTPUT)/foo_test: foo_test.c $(BPF_SKELS)
#         $(call bpf_link,$@,$<)
#
# Optional knobs (set before including lib.bpf.mk):
#   BPF_PROG_EXT     - source suffix, default .bpf.c; set to .c for the legacy
#                      "progs/foo.c -> foo.bpf.o" layout.
#   BPF_EXTRA_HDRS   - extra prerequisites (headers) for the BPF objects.
#   BPF_EXTRA_CFLAGS - appended to BPF_CFLAGS for the BPF compile.
#   BPF_SKEL_EXT     - skeleton suffix, default .skel.h (e.g. .bpf.skel.h).
#   BPF_GEN_SUBSKEL  - if set, also emit a subskeleton next to each skeleton.
#   BPF_OBJ_DIR      - dir for generated *.bpf.o (default $(OUTPUT)).
#   BPF_SKEL_DIR     - dir for generated skeletons (default $(OUTPUT)).
# A caller with unusual compile needs may override BPF_CFLAGS wholesale after
# the include (the object recipe expands it lazily).
# BPF_SRCS entries may live in a subdirectory (e.g. progs/foo.bpf.c); the
# objects and skeletons are always emitted flat under $(OUTPUT), keyed by the
# source basename (foo.bpf.o / foo.skel.h).
#
# lib.mk MUST be included first: this fragment consumes the vars it defines
# (OUTPUT, top_srcdir, CC, CLANG, Q, msg) and needs OVERRIDE_TARGETS to have
# already suppressed lib.mk's default link rule.

include $(top_srcdir)/tools/scripts/Makefile.arch	# ARCH / SRCARCH
# Pull in the shared toolchain definitions (HOSTCC/HOSTLD/CLANG) so this
# fragment picks the *same* host compiler the libbpf and bpftool sub-makes
# will: in particular HOSTCC becomes clang under LLVM=1 (gcc otherwise).
# Without this the host bpftool and its bootstrap libbpf can end up built with
# a mix of gcc and clang, which trips clang on gcc-only flags (-Wstrict-aliasing=3).
#
# Makefile.include's allow-override resets CC to a bare "clang", which would
# drop the --target=<arch> flag lib.mk set for LLVM=1 cross builds (make LLVM=1
# ARCH=arm64).  lib.mk ran first and configured CC for the target, so save it
# across the include and restore it afterwards.
lib_bpf_mk_saved_cc := $(CC)
include $(top_srcdir)/tools/scripts/Makefile.include
CC := $(lib_bpf_mk_saved_cc)

CLANG  ?= clang
HOSTCC ?= gcc
HOSTLD ?= ld
ifneq ($(V),1)
submake_extras := feature_display=0
endif

# ---- paths & tools --------------------------------------------------------
TOOLSDIR    := $(top_srcdir)/tools
LIBDIR      := $(TOOLSDIR)/lib
BPFDIR      := $(LIBDIR)/bpf
TOOLSINCDIR := $(TOOLSDIR)/include
BPFTOOLDIR  := $(TOOLSDIR)/bpf/bpftool
APIDIR      := $(TOOLSINCDIR)/uapi

# Everything generated lives under $(OUTPUT) so O= and in-tree both work and
# per-test builds (distinct $(OUTPUT)) never collide.
SCRATCH_DIR := $(OUTPUT)/tools
BUILD_DIR   := $(SCRATCH_DIR)/build
INCLUDE_DIR := $(SCRATCH_DIR)/include
BPFOBJ      := $(BUILD_DIR)/libbpf/libbpf.a

# bpftool must run on the *host*; split the host toolchain out when cross-building.
ifneq ($(CROSS_COMPILE),)
HOST_BUILD_DIR   := $(BUILD_DIR)/host
HOST_SCRATCH_DIR := $(OUTPUT)/host-tools
else
HOST_BUILD_DIR   := $(BUILD_DIR)
HOST_SCRATCH_DIR := $(SCRATCH_DIR)
endif
HOST_BPFOBJ     := $(HOST_BUILD_DIR)/libbpf/libbpf.a
DEFAULT_BPFTOOL := $(HOST_SCRATCH_DIR)/sbin/bpftool
BPFTOOL         ?= $(DEFAULT_BPFTOOL)

# ---- vmlinux BTF discovery -----------------------------------------------
VMLINUX_BTF_PATHS ?= $(if $(O),$(O)/vmlinux)				\
		     $(if $(KBUILD_OUTPUT),$(KBUILD_OUTPUT)/vmlinux)	\
		     $(top_srcdir)/vmlinux				\
		     /sys/kernel/btf/vmlinux				\
		     /boot/vmlinux-$(shell uname -r)
VMLINUX_BTF ?= $(abspath $(firstword $(wildcard $(VMLINUX_BTF_PATHS))))
ifeq ($(VMLINUX_BTF),)
$(error Cannot find a vmlinux for VMLINUX_BTF at any of "$(VMLINUX_BTF_PATHS)")
endif

# ---- clang flags ----------------------------------------------------------
# Clang's default system includes (not the ones seen under --target=bpf); fixes
# "missing" asm/byteorder.h etc. '-idirafter' so we never shadow real includes.
define get_sys_includes
$(shell $(1) $(2) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }') \
$(shell $(1) $(2) -dM -E - </dev/null | grep '__riscv_xlen ' | awk '{printf("-D__riscv_xlen=%d -D__BITS_PER_LONG=%d", $$3, $$3)}')
endef
ifneq ($(CROSS_COMPILE),)
CLANG_TARGET_ARCH = --target=$(notdir $(CROSS_COMPILE:%-=%))
endif
CLANG_SYS_INCLUDES = $(call get_sys_includes,$(CLANG),$(CLANG_TARGET_ARCH))

IS_LITTLE_ENDIAN = $(shell $(CC) -dM -E - </dev/null | \
			grep 'define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__')
MENDIAN = $(if $(IS_LITTLE_ENDIAN),-mlittle-endian,-mbig-endian)

# Prefer -mcpu=v3; fall back to v2 on clang too old to know it (probed once).
CLANG_BPF_CPU := $(shell $(CLANG) --target=bpf -mcpu=help 2>&1 | grep -q 'v3' \
			 && echo v3 || echo v2)

# -fms-extensions + -Wno-microsoft-anon-tag: required so clang accepts the
# anonymous nested struct/union members bpftool emits into vmlinux.h.
BPF_CFLAGS = -g -Wall -Werror -D__TARGET_ARCH_$(SRCARCH) $(MENDIAN)	\
	     -I$(INCLUDE_DIR) -I$(APIDIR) -I$(TOOLSINCDIR)		\
	     -std=gnu11							\
	     -fno-strict-aliasing					\
	     -fms-extensions -Wno-microsoft-anon-tag			\
	     -Wno-compare-distinct-pointer-types			\
	     $(CLANG_SYS_INCLUDES) $(BPF_EXTRA_CFLAGS)

# $1 = src .bpf.c, $2 = dst .bpf.o
define BPF_BUILD_RULE
	$(call msg,CLNG-BPF,,$2)
	$(Q)$(CLANG) $(BPF_CFLAGS) -O2 --target=bpf -mcpu=$(CLANG_BPF_CPU) -c $1 -o $2
endef

# ---- output dirs for generated objects/skeletons --------------------------
# Default: flat under $(OUTPUT) (what bpf/, hid/, cgroup/ do).  A caller may
# segregate the generated files into subdirs, e.g. BPF_SKEL_DIR := $(OUTPUT)/...
BPF_OBJ_DIR  ?= $(OUTPUT)
BPF_SKEL_DIR ?= $(OUTPUT)

# ---- scratch dirs ---------------------------------------------------------
MAKE_DIRS := $(sort $(BUILD_DIR)/libbpf $(HOST_BUILD_DIR)/libbpf		\
		    $(HOST_BUILD_DIR)/bpftool $(INCLUDE_DIR)		\
		    $(filter-out $(OUTPUT),$(BPF_OBJ_DIR) $(BPF_SKEL_DIR)))
$(MAKE_DIRS):
	$(call msg,MKDIR,,$@)
	$(Q)mkdir -p $@

# ---- libbpf (target) ------------------------------------------------------
# Pass ARCH/CROSS_COMPILE/CC through: lib.mk's CC is file-origin and is not
# exported, so without this the libbpf sub-make would rebuild for the host under
# a pure-LLVM cross build (make LLVM=1 ARCH=<arch>).  -fPIC keeps the static
# libbpf linkable into position-independent (PIE) test binaries.
$(BPFOBJ): $(wildcard $(BPFDIR)/*.[ch] $(BPFDIR)/Makefile) \
	   $(APIDIR)/linux/bpf.h | $(BUILD_DIR)/libbpf
	$(Q)$(MAKE) $(submake_extras) -C $(BPFDIR) OUTPUT=$(BUILD_DIR)/libbpf/ \
		    ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) CC="$(CC)"     \
		    EXTRA_CFLAGS='-g -O0 -fPIC'				      \
		    DESTDIR=$(SCRATCH_DIR) prefix= all install_headers

# ---- libbpf (host) -- a distinct rule only when cross-compiling -----------
ifneq ($(BPFOBJ),$(HOST_BPFOBJ))
$(HOST_BPFOBJ): $(wildcard $(BPFDIR)/*.[ch] $(BPFDIR)/Makefile) \
		| $(HOST_BUILD_DIR)/libbpf
	$(Q)$(MAKE) $(submake_extras) -C $(BPFDIR) ARCH= CROSS_COMPILE=	      \
		    OUTPUT=$(HOST_BUILD_DIR)/libbpf/ CC=$(HOSTCC) LD=$(HOSTLD) \
		    EXTRA_CFLAGS='-g -O0'				      \
		    DESTDIR=$(HOST_SCRATCH_DIR) prefix= all install_headers
endif

# ---- bpftool (host) -------------------------------------------------------
$(DEFAULT_BPFTOOL): $(wildcard $(BPFTOOLDIR)/*.[ch] $(BPFTOOLDIR)/Makefile) \
		    $(HOST_BPFOBJ) | $(HOST_BUILD_DIR)/bpftool
	$(Q)$(MAKE) $(submake_extras) -C $(BPFTOOLDIR)		  \
		    ARCH= CROSS_COMPILE= CC=$(HOSTCC) LD=$(HOSTLD) \
		    EXTRA_CFLAGS='-g -O0'			  \
		    OUTPUT=$(HOST_BUILD_DIR)/bpftool/		  \
		    LIBBPF_OUTPUT=$(HOST_BUILD_DIR)/libbpf/	  \
		    LIBBPF_DESTDIR=$(HOST_SCRATCH_DIR)/		  \
		    prefix= DESTDIR=$(HOST_SCRATCH_DIR)/ install-bin

# ---- vmlinux.h ------------------------------------------------------------
$(INCLUDE_DIR)/vmlinux.h: $(VMLINUX_BTF) $(BPFTOOL) | $(INCLUDE_DIR)
ifeq ($(VMLINUX_H),)
	$(call msg,GEN,,$@)
	$(Q)$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@
else
	$(call msg,CP,,$@)
	$(Q)cp "$(VMLINUX_H)" $@
endif

# ---- BPF objects + skeletons ---------------------------------------------
# Sources may sit in a subdir and use the modern *.bpf.c or the legacy *.c
# suffix (BPF_PROG_EXT); objects go in $(BPF_OBJ_DIR) and skeletons in
# $(BPF_SKEL_DIR) (both default to $(OUTPUT)), keyed by the source basename.
BPF_PROG_EXT ?= .bpf.c
bpf_stems := $(patsubst %$(BPF_PROG_EXT),%,$(notdir $(BPF_SRCS)))
# The output namespace is flat, so two sources with the same basename would
# collapse into one object/skeleton; fail loudly instead of silently dropping.
ifneq ($(words $(bpf_stems)),$(words $(sort $(bpf_stems))))
$(error lib.bpf.mk: BPF_SRCS has colliding basenames: $(BPF_SRCS))
endif
# BPF_SKEL_EXT lets a caller pick the skeleton suffix (default .skel.h; e.g.
# .bpf.skel.h).  With BPF_GEN_SUBSKEL set, a matching subskeleton is emitted
# alongside (foo.subskel.h / foo.bpf.subskel.h).
BPF_SKEL_EXT    ?= .skel.h
BPF_SUBSKEL_EXT := $(patsubst %skel.h,%subskel.h,$(BPF_SKEL_EXT))
BPF_OBJS  := $(addprefix $(BPF_OBJ_DIR)/,$(addsuffix .bpf.o,$(bpf_stems)))
BPF_SKELS := $(addprefix $(BPF_SKEL_DIR)/,$(addsuffix $(BPF_SKEL_EXT),$(bpf_stems)))

# Locate the sources wherever the caller keeps them (e.g. progs/).
vpath %$(BPF_PROG_EXT) $(sort $(dir $(BPF_SRCS)))

$(BPF_OBJS): $(BPF_OBJ_DIR)/%.bpf.o: %$(BPF_PROG_EXT) $(BPF_EXTRA_HDRS) \
	     $(wildcard *.bpf.h) $(INCLUDE_DIR)/vmlinux.h | $(BPF_OBJ_DIR) $(BPFOBJ)
	$(call BPF_BUILD_RULE,$<,$@)

$(BPF_SKELS): $(BPF_SKEL_DIR)/%$(BPF_SKEL_EXT): $(BPF_OBJ_DIR)/%.bpf.o $(BPFTOOL) | $(BPF_SKEL_DIR)
	$(call msg,GEN-SKEL,,$@)
	$(Q)$(BPFTOOL) gen object $(<:.o=.linked.o) $<
	$(Q)$(BPFTOOL) gen skeleton $(<:.o=.linked.o) name $(notdir $(<:.bpf.o=)) > $@
ifneq ($(BPF_GEN_SUBSKEL),)
	$(Q)$(BPFTOOL) gen subskeleton $(<:.o=.linked.o) name $(notdir $(<:.bpf.o=)) > $(@:$(BPF_SKEL_EXT)=$(BPF_SUBSKEL_EXT))
endif

# ---- exports consumed by the caller --------------------------------------
# -I$(OUTPUT)/-I$(BPF_SKEL_DIR): so the test .c can #include "foo.skel.h".
# -I$(INCLUDE_DIR): so userspace can pull in the generated vmlinux.h if needed.
CFLAGS += -I$(OUTPUT) -I$(BPF_SKEL_DIR) -I$(INCLUDE_DIR)

# Static libbpf.a first, then its deps. libbpf may pull in zstd (BTF decompress)
# only when built against it; link -lzstd only if libzstd is present.
BPF_LDLIBS := $(BPFOBJ) -lelf -lz
ifneq ($(shell pkg-config --exists libzstd 2>/dev/null && echo y),)
BPF_LDLIBS += -lzstd
endif

TEST_GEN_FILES += $(BPF_OBJS)

# Link helper: $1 = output binary, $2 = test .c (skels are the target's deps).
define bpf_link
	$(call msg,BINARY,,$1)
	$(Q)$(CC) $(CFLAGS) $2 $(BPF_LDLIBS) $(LDLIBS) -o $1
endef

EXTRA_CLEAN += $(SCRATCH_DIR) $(HOST_SCRATCH_DIR)			\
	       $(addprefix $(BPF_OBJ_DIR)/,*.bpf.o *.linked.o)		\
	       $(addprefix $(BPF_SKEL_DIR)/,*$(BPF_SKEL_EXT) *$(BPF_SUBSKEL_EXT))
