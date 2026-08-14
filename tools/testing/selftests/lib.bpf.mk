# SPDX-License-Identifier: GPL-2.0
#
# Build BPF programs and skeleton headers for selftests, then link them into
# test binaries.
#
# Use it from a test Makefile like this:
#
#     BPF_SRCS         := foo.bpf.c bar.bpf.c
#     TEST_GEN_PROGS   := foo_test
#     OVERRIDE_TARGETS := 1              # set before lib.mk
#     include ../lib.mk
#     include ../lib.bpf.mk
#
#     $(OUTPUT)/foo_test: foo_test.c $(BPF_SKELS) $(BPFOBJ)
#         $(call bpf_link,$@,$<)
#
# Keep $(BPFOBJ) in the dependencies so make relinks the test when libbpf.a
# changes.
#
# Options to set before including lib.bpf.mk:
#   BPF_PROG_EXT     - source ending; default .bpf.c. Use .c for progs/foo.c.
#   BPF_EXTRA_HDRS   - more headers needed by the BPF objects.
#   BPF_EXTRA_CFLAGS - more flags for compiling BPF programs.
#   BPF_SKEL_EXT     - skeleton header ending; default .skel.h.
#   BPF_GEN_SUBSKEL  - also create a subskeleton header when set.
#   BPF_OBJ_DIR      - folder for BPF objects; default $(OUTPUT).
#   BPF_SKEL_DIR     - folder for skeleton headers; default $(OUTPUT).
#
# You may replace BPF_CFLAGS after including this file. Make reads it when each
# object is built. Sources may be in subfolders, but generated files use only
# the source filename and are placed directly in their output folder.
#
# Include lib.mk first. This file uses OUTPUT, top_srcdir, CC, CLANG, Q and msg.
# OVERRIDE_TARGETS stops lib.mk from adding its normal link rule. This file sets
# BPFOBJ, BPFTOOL, BPF_OBJS, BPF_SKELS and BPF_LDLIBS, and adds to CFLAGS and
# EXTRA_CLEAN.

include $(top_srcdir)/tools/scripts/Makefile.arch	# ARCH / SRCARCH / HOSTARCH

# Some commands write bpftool output straight to $@. Remove a partial file when
# a command fails.
.DELETE_ON_ERROR:

# Use matching host tools for libbpf and bpftool. This keeps an LLVM build from
# mixing Clang and GCC. Makefile.include is not used because it would also
# change the test's AR, LD, CXX and CFLAGS.
ifneq ($(LLVM),)
HOSTCC ?= $(LLVM_PREFIX)clang$(LLVM_SUFFIX)
HOSTLD ?= $(LLVM_PREFIX)ld.lld$(LLVM_SUFFIX)
else
HOSTCC ?= gcc
HOSTLD ?= ld
endif
CLANG  ?= clang

ifneq ($(V),1)
submake_extras := feature_display=0
endif

# Pass RELEASE, OPT_FLAGS and EXTRA_CFLAGS to the libbpf and bpftool builds,
# matching selftests/bpf/Makefile.
OPT_FLAGS ?= $(if $(RELEASE),-O2,-O0)

# ---- files and tools ------------------------------------------------------
# Use one full path. Different forms of the same -I path can change BTF order.
TOOLSDIR    := $(abspath $(top_srcdir)/tools)
LIBDIR      := $(TOOLSDIR)/lib
BPFDIR      := $(LIBDIR)/bpf
TOOLSINCDIR := $(TOOLSDIR)/include
BPFTOOLDIR  := $(TOOLSDIR)/bpf/bpftool
APIDIR      := $(TOOLSINCDIR)/uapi

# Keep private build files under $(OUTPUT) for both in-tree and O= builds.
SCRATCH_DIR := $(OUTPUT)/tools
BUILD_DIR   := $(SCRATCH_DIR)/build
INCLUDE_DIR := $(SCRATCH_DIR)/include
BPFOBJ      := $(BUILD_DIR)/libbpf/libbpf.a

# bpftool runs on the build host. Build a separate host libbpf when the target
# architecture is different.
ifneq ($(CROSS_COMPILE)$(filter-out $(HOSTARCH),$(SRCARCH)),)
HOST_BUILD_DIR   := $(BUILD_DIR)/host
HOST_SCRATCH_DIR := $(OUTPUT)/host-tools
else
HOST_BUILD_DIR   := $(BUILD_DIR)
HOST_SCRATCH_DIR := $(SCRATCH_DIR)
endif
HOST_BPFOBJ     := $(HOST_BUILD_DIR)/libbpf/libbpf.a
DEFAULT_BPFTOOL := $(HOST_SCRATCH_DIR)/sbin/bpftool
BPFTOOL         ?= $(DEFAULT_BPFTOOL)

# When host and target are the same, bpftool uses the target libbpf and needs
# the same USERCFLAGS. Do not pass USERCFLAGS to separate host tools.
ifeq ($(BPFOBJ),$(HOST_BPFOBJ))
HOST_USERCFLAGS := $(USERCFLAGS)
endif

# ---- find vmlinux BTF -----------------------------------------------------
VMLINUX_BTF_PATHS ?= $(if $(O),$(O)/vmlinux)				\
		     $(if $(KBUILD_OUTPUT),$(KBUILD_OUTPUT)/vmlinux)	\
		     $(top_srcdir)/vmlinux				\
		     /sys/kernel/btf/vmlinux				\
		     /boot/vmlinux-$(shell uname -r)
VMLINUX_BTF ?= $(abspath $(firstword $(wildcard $(VMLINUX_BTF_PATHS))))
# When VMLINUX_H is not set, report a missing vmlinux only while building
# vmlinux.h. Reporting it here would also make "make clean" fail.

# ---- compiler flags -------------------------------------------------------
# Find the normal system headers that Clang omits with --target=bpf. Put them
# last with -idirafter so they cannot replace project headers.
define get_sys_includes
$(shell $(1) $(2) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }') \
$(shell $(1) $(2) -dM -E - </dev/null | grep '__riscv_xlen ' | awk '{printf("-D__riscv_xlen=%d -D__BITS_PER_LONG=%d", $$3, $$3)}')
endef
ifneq ($(CROSS_COMPILE),)
CLANG_TARGET_ARCH = --target=$(notdir $(CROSS_COMPILE:%-=%))
endif
# Find the system include flags once and reuse them.
CLANG_SYS_INCLUDES := $(call get_sys_includes,$(CLANG),$(CLANG_TARGET_ARCH))

IS_LITTLE_ENDIAN := $(shell $(CC) -dM -E - </dev/null | \
			grep 'define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__')
MENDIAN := $(if $(IS_LITTLE_ENDIAN),-mlittle-endian,-mbig-endian)

# Use BPF CPU v3 when Clang supports it. Otherwise use v2.
CLANG_BPF_CPU := $(shell $(CLANG) --target=bpf -mcpu=help 2>&1 | grep -q 'v3' \
			 && echo v3 || echo v2)

# vmlinux.h can contain anonymous struct and union members. Clang needs
# -fms-extensions to accept them.
BPF_CFLAGS = -g -Wall -Werror -D__TARGET_ARCH_$(SRCARCH) $(MENDIAN)	\
	     -I$(INCLUDE_DIR) -I$(APIDIR) -I$(TOOLSINCDIR)		\
	     -std=gnu11							\
	     -fno-strict-aliasing					\
	     -fms-extensions -Wno-microsoft-anon-tag			\
	     -Wno-compare-distinct-pointer-types			\
	     $(CLANG_SYS_INCLUDES) $(BPF_EXTRA_CFLAGS)

# $1 = source, $2 = object. -MMD -MP records every included header, including
# headers included by other headers.
define BPF_BUILD_RULE
	$(call msg,CLNG-BPF,,$2)
	$(Q)$(CLANG) $(BPF_CFLAGS) -O2 --target=bpf -mcpu=$(CLANG_BPF_CPU) \
		-MMD -MP -c $1 -o $2
endef

# ---- output folders -------------------------------------------------------
BPF_OBJ_DIR  ?= $(OUTPUT)
BPF_SKEL_DIR ?= $(OUTPUT)

# ---- build folders --------------------------------------------------------
MAKE_DIRS := $(sort $(BUILD_DIR)/libbpf $(HOST_BUILD_DIR)/libbpf		\
		    $(HOST_BUILD_DIR)/bpftool $(INCLUDE_DIR)		\
		    $(filter-out $(OUTPUT),$(BPF_OBJ_DIR) $(BPF_SKEL_DIR)))
$(MAKE_DIRS):
	$(call msg,MKDIR,,$@)
	$(Q)mkdir -p $@

# ---- target libbpf --------------------------------------------------------
# Pass ARCH, CROSS_COMPILE and CC because lib.mk does not export CC. -fPIC lets
# libbpf.a link into PIE test binaries. libbpf reads EXTRA_CFLAGS, so pass
# USERCFLAGS there too.
$(BPFOBJ): $(wildcard $(BPFDIR)/*.[ch] $(BPFDIR)/Makefile) \
	   $(APIDIR)/linux/bpf.h | $(BUILD_DIR)/libbpf
	$(Q)$(MAKE) $(submake_extras) -C $(BPFDIR) OUTPUT=$(BUILD_DIR)/libbpf/ \
		    ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) CC="$(CC)"     \
		    EXTRA_CFLAGS='-g $(OPT_FLAGS) -fPIC $(EXTRA_CFLAGS) $(USERCFLAGS)' \
		    DESTDIR=$(SCRATCH_DIR) prefix= all install_headers

# ---- host libbpf, only when the target differs ----------------------------
ifneq ($(BPFOBJ),$(HOST_BPFOBJ))
$(HOST_BPFOBJ): $(wildcard $(BPFDIR)/*.[ch] $(BPFDIR)/Makefile) \
		$(APIDIR)/linux/bpf.h | $(HOST_BUILD_DIR)/libbpf
	$(Q)$(MAKE) $(submake_extras) -C $(BPFDIR) ARCH= CROSS_COMPILE=	      \
		    OUTPUT=$(HOST_BUILD_DIR)/libbpf/ CC="$(HOSTCC)" LD="$(HOSTLD)" \
		    EXTRA_CFLAGS='-g $(OPT_FLAGS) $(EXTRA_CFLAGS)' \
		    DESTDIR=$(HOST_SCRATCH_DIR) prefix= all install_headers
endif

# ---- host bpftool ---------------------------------------------------------
$(DEFAULT_BPFTOOL): $(wildcard $(BPFTOOLDIR)/*.[ch] $(BPFTOOLDIR)/Makefile) \
		    $(HOST_BPFOBJ) | $(HOST_BUILD_DIR)/bpftool
	$(Q)$(MAKE) $(submake_extras) -C $(BPFTOOLDIR)		  \
		    ARCH= CROSS_COMPILE= CC="$(HOSTCC)" LD="$(HOSTLD)" \
		    EXTRA_CFLAGS='-g $(OPT_FLAGS) $(EXTRA_CFLAGS) $(HOST_USERCFLAGS)' \
		    EXTRA_LDFLAGS='$(EXTRA_LDFLAGS)'		  \
		    OUTPUT=$(HOST_BUILD_DIR)/bpftool/		  \
		    LIBBPF_OUTPUT=$(HOST_BUILD_DIR)/libbpf/	  \
		    LIBBPF_DESTDIR=$(HOST_SCRATCH_DIR)/		  \
		    prefix= DESTDIR=$(HOST_SCRATCH_DIR)/ install-bin

# ---- build vmlinux.h ------------------------------------------------------
# Replace vmlinux.h only when its contents change. A new timestamp alone would
# rebuild every BPF object and skeleton.
$(INCLUDE_DIR)/vmlinux.h: $(VMLINUX_BTF) $(BPFTOOL) | $(INCLUDE_DIR)
ifeq ($(VMLINUX_H),)
	$(call msg,GEN,,$@)
	$(Q)test -n "$(VMLINUX_BTF)" || { \
		echo "lib.bpf.mk: no vmlinux with BTF at any of \"$(VMLINUX_BTF_PATHS)\"" >&2; \
		exit 1; }
	$(Q)$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@.tmp
else
	$(call msg,CP,,$@)
	$(Q)cp "$(VMLINUX_H)" $@.tmp
endif
	$(Q)cmp -s $@.tmp $@ || mv $@.tmp $@
	$(Q)rm -f $@.tmp

# ---- BPF objects and skeletons --------------------------------------------
BPF_PROG_EXT ?= .bpf.c
# Each source must end with BPF_PROG_EXT so Make can remove that ending.
bpf_bad_srcs := $(filter-out %$(BPF_PROG_EXT),$(BPF_SRCS))
ifneq ($(bpf_bad_srcs),)
$(error lib.bpf.mk: BPF_SRCS entries must end in $(BPF_PROG_EXT): $(bpf_bad_srcs))
endif
bpf_stems := $(patsubst %$(BPF_PROG_EXT),%,$(notdir $(BPF_SRCS)))
# Reject any dot left after removing BPF_PROG_EXT. For example, foo.bpf.c leaves
# foo.bpf when the ending is set to .c.
bpf_dotted_stems := $(filter-out $(basename $(bpf_stems)),$(bpf_stems))
ifneq ($(bpf_dotted_stems),)
$(error lib.bpf.mk: BPF_SRCS basenames must not contain a dot: $(bpf_dotted_stems))
endif
# Generated files use only the source filename. Reject equal filenames instead
# of letting one replace another.
ifneq ($(words $(bpf_stems)),$(words $(sort $(bpf_stems))))
$(error lib.bpf.mk: BPF_SRCS has colliding basenames: $(BPF_SRCS))
endif
BPF_SKEL_EXT    ?= .skel.h
BPF_SUBSKEL_EXT := $(patsubst %skel.h,%subskel.h,$(BPF_SKEL_EXT))
# BPF_SKEL_EXT must end in skel.h so the subskeleton gets a different name.
ifneq ($(BPF_GEN_SUBSKEL),)
ifeq ($(BPF_SUBSKEL_EXT),$(BPF_SKEL_EXT))
$(error lib.bpf.mk: BPF_GEN_SUBSKEL needs BPF_SKEL_EXT to end in skel.h: $(BPF_SKEL_EXT))
endif
endif
BPF_OBJS  := $(addprefix $(BPF_OBJ_DIR)/,$(addsuffix .bpf.o,$(bpf_stems)))
BPF_SKELS := $(addprefix $(BPF_SKEL_DIR)/,$(addsuffix $(BPF_SKEL_EXT),$(bpf_stems)))

# Make one rule for each source. A global vpath would also match the test's
# normal C rules when BPF_PROG_EXT is .c.
define bpf_obj_rule
$(BPF_OBJ_DIR)/$(patsubst %$(BPF_PROG_EXT),%,$(notdir $(1))).bpf.o: $(1)	\
		$(BPF_EXTRA_HDRS) $(INCLUDE_DIR)/vmlinux.h			\
		| $(BPF_OBJ_DIR) $(BPFOBJ)
	$$(call BPF_BUILD_RULE,$$<,$$@)
endef
$(foreach src,$(BPF_SRCS),$(eval $(call bpf_obj_rule,$(src))))

# Link three times and compare the last two outputs. A correct linker must not
# change an object that it already linked.
$(BPF_SKELS): $(BPF_SKEL_DIR)/%$(BPF_SKEL_EXT): $(BPF_OBJ_DIR)/%.bpf.o $(BPFTOOL) | $(BPF_SKEL_DIR)
	$(call msg,GEN-SKEL,,$@)
	$(Q)$(BPFTOOL) gen object $(<:.o=.linked1.o) $<
	$(Q)$(BPFTOOL) gen object $(<:.o=.linked2.o) $(<:.o=.linked1.o)
	$(Q)$(BPFTOOL) gen object $(<:.o=.linked3.o) $(<:.o=.linked2.o)
	$(Q)diff $(<:.o=.linked2.o) $(<:.o=.linked3.o)
	$(Q)$(BPFTOOL) gen skeleton $(<:.o=.linked3.o) name $(notdir $(<:.bpf.o=)) > $@
ifneq ($(BPF_GEN_SUBSKEL),)
	$(Q)$(BPFTOOL) gen subskeleton $(<:.o=.linked3.o) name $(notdir $(<:.bpf.o=)) > $(@:$(BPF_SKEL_EXT)=$(BPF_SUBSKEL_EXT))
endif
	$(Q)rm -f $(<:.o=.linked1.o) $(<:.o=.linked2.o) $(<:.o=.linked3.o)

# Read the header dependencies written by -MMD.
-include $(BPF_OBJS:.o=.d)

# ---- values for the test Makefile -----------------------------------------
# Add paths for generated skeletons and vmlinux.h. Put the new libbpf headers
# first so an older copy under BPF_SKEL_DIR cannot be used by mistake.
CFLAGS += -I$(INCLUDE_DIR) -I$(OUTPUT) -I$(BPF_SKEL_DIR)

# Add target zstd when pkg-config finds it. A cross build must use the target
# pkg-config, not the host one.
PKG_CONFIG ?= $(CROSS_COMPILE)pkg-config
BPF_LDLIBS := $(BPFOBJ) -lelf -lz
ifneq ($(shell $(PKG_CONFIG) --exists libzstd 2>/dev/null && echo y),)
BPF_LDLIBS += -lzstd
endif

# lib.mk made its "all" list before this file was included. Add the skeletons
# here so they are built.
all: $(BPF_SKELS)

# The skeleton already embeds each BPF object in the test binary. To install the
# objects separately, add TEST_GEN_FILES += $(BPF_OBJS).

# $1 = binary, $2 = test source. Use the same compile and link flags as lib.mk.
define bpf_link
	$(call msg,BINARY,,$1)
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(TARGET_ARCH) $2 \
		$(BPF_LDLIBS) $(LDLIBS) -o $1
endef

EXTRA_CLEAN += $(sort $(SCRATCH_DIR) $(HOST_SCRATCH_DIR))		\
	       $(addprefix $(BPF_OBJ_DIR)/,*.bpf.o *.bpf.d *.linked*.o)	\
	       $(addprefix $(BPF_SKEL_DIR)/,*$(BPF_SKEL_EXT) *$(BPF_SUBSKEL_EXT))
