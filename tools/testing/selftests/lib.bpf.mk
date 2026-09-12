# SPDX-License-Identifier: GPL-2.0
#
# Build BPF programs and skeletons for selftests.
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
# Depend on $(BPFOBJ) to relink the test when libbpf.a changes.
#
# Options to set before including lib.bpf.mk:
#   BPF_PROG_EXT     - source ending; default .bpf.c. Use .c for progs/foo.c.
#   BPF_EXTRA_HDRS   - more headers needed by the BPF objects.
#   BPF_EXTRA_CFLAGS - more flags for compiling BPF programs.
#   BPF_SKEL_EXT     - skeleton header ending; default .skel.h. Must end in
#                      skel.h.
#   BPF_GEN_SUBSKEL  - also create a subskeleton header when set.
#   BPF_OBJ_DIR      - folder for BPF objects; default $(OUTPUT).
#   BPF_SKEL_DIR     - folder for skeleton headers; default $(OUTPUT).
#
# Set output directories that use $(OUTPUT) after including lib.mk.
#
# BPF_CFLAGS may be replaced after this include. Generated names use the source
# stem without its directory.
#
# Include lib.mk first. This file defines the BPF build variables and bpf_link,
# extends all, CFLAGS and EXTRA_CLEAN, and enables .DELETE_ON_ERROR.

include $(top_srcdir)/tools/scripts/Makefile.arch	# ARCH / SRCARCH / HOSTARCH

# Remove partial files written directly to $@.
.DELETE_ON_ERROR:

# Match the libbpf and bpftool host compiler to LLVM=.
ifneq ($(LLVM),)
HOSTCC ?= $(LLVM_PREFIX)clang$(LLVM_SUFFIX)
HOSTLD ?= $(LLVM_PREFIX)ld.lld$(LLVM_SUFFIX)
else
HOSTCC ?= gcc
HOSTLD ?= ld
endif
CLANG  ?= clang

ifneq ($(V),1)
lib_bpf_submake_extras := feature_display=0
endif

# Match selftests/bpf debug and release optimization.
OPT_FLAGS ?= $(if $(RELEASE),-O2,-O0)

# ---- files and tools ------------------------------------------------------
# Use one full path. Different forms of the same -I path can change BTF order.
lib_bpf_tools_dir         := $(abspath $(top_srcdir)/tools)
lib_bpf_dir               := $(lib_bpf_tools_dir)/lib/bpf
lib_bpf_tools_include_dir := $(lib_bpf_tools_dir)/include
lib_bpf_bpftool_dir       := $(lib_bpf_tools_dir)/bpf/bpftool
lib_bpf_api_dir           := $(lib_bpf_tools_include_dir)/uapi
lib_bpf_sources           := $(wildcard $(lib_bpf_dir)/*.[ch] \
					       $(lib_bpf_dir)/Makefile)
lib_bpf_header_sources    := $(filter %.h,$(lib_bpf_sources)) \
				     $(lib_bpf_api_dir)/linux/bpf.h
# Keep these names for callers which add their own BPF flags or dependencies.
BPFDIR     := $(lib_bpf_dir)
APIDIR     := $(lib_bpf_api_dir)

# Keep private build files under $(OUTPUT) for both in-tree and O= builds.
lib_bpf_scratch_dir := $(OUTPUT)/tools
lib_bpf_build_dir   := $(lib_bpf_scratch_dir)/build
lib_bpf_include_dir := $(lib_bpf_scratch_dir)/include
# INCLUDE_DIR is also used by callers that replace BPF_CFLAGS.
INCLUDE_DIR := $(lib_bpf_include_dir)
BPFOBJ      := $(lib_bpf_build_dir)/libbpf/libbpf.a

# Cross builds use a separate native libbpf for bpftool.
ifneq ($(CROSS_COMPILE)$(filter-out $(HOSTARCH),$(SRCARCH)),)
lib_bpf_host_build_dir   := $(lib_bpf_build_dir)/host
lib_bpf_host_scratch_dir := $(OUTPUT)/host-tools
else
lib_bpf_host_build_dir   := $(lib_bpf_build_dir)
lib_bpf_host_scratch_dir := $(lib_bpf_scratch_dir)
endif
lib_bpf_host_obj := $(lib_bpf_host_build_dir)/libbpf/libbpf.a
DEFAULT_BPFTOOL  := $(lib_bpf_host_scratch_dir)/sbin/bpftool
BPFTOOL          ?= $(DEFAULT_BPFTOOL)

# Reuse target USERCFLAGS only when bpftool shares the target libbpf.
ifeq ($(BPFOBJ),$(lib_bpf_host_obj))
lib_bpf_host_user_cflags := $(USERCFLAGS)
endif

# ---- find vmlinux BTF -----------------------------------------------------
VMLINUX_BTF_PATHS ?= $(if $(O),$(O)/vmlinux)				\
		     $(if $(KBUILD_OUTPUT),$(KBUILD_OUTPUT)/vmlinux)	\
		     $(top_srcdir)/vmlinux				\
		     /sys/kernel/btf/vmlinux				\
		     /boot/vmlinux-$(shell uname -r)
VMLINUX_BTF ?= $(abspath $(firstword $(wildcard $(VMLINUX_BTF_PATHS))))
# Delay missing-vmlinux errors so "make clean" still works.
lib_bpf_vmlinux_deps := $(if $(VMLINUX_H),$(VMLINUX_H),$(VMLINUX_BTF) $(BPFTOOL))

# ---- compiler flags -------------------------------------------------------
# Find the normal system headers that Clang omits with --target=bpf. Put them
# last with -idirafter so they cannot replace project headers.
define lib_bpf_get_sys_includes
$(shell $(1) $(2) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }') \
$(shell $(1) $(2) -dM -E - </dev/null | grep '__riscv_xlen ' | awk '{printf("-D__riscv_xlen=%d -D__BITS_PER_LONG=%d", $$3, $$3)}') \
$(shell $(1) $(2) -dM -E - </dev/null | grep '__loongarch_grlen ' | awk '{printf("-D__BITS_PER_LONG=%d", $$3)}') \
$(shell $(1) $(2) -dM -E - </dev/null | grep -E 'MIPS(EL|EB)|_MIPS_SZ(PTR|LONG) |_MIPS_SIM |_ABI(O32|N32|64) ' | awk '{printf("-D%s=%s ", $$2, $$3)}')
endef
ifneq ($(CROSS_COMPILE),)
lib_bpf_clang_target_arch = --target=$(notdir $(CROSS_COMPILE:%-=%))
endif
# Find the system include flags once and reuse them.
CLANG_SYS_INCLUDES := $(call lib_bpf_get_sys_includes,$(CLANG),$(lib_bpf_clang_target_arch))

lib_bpf_is_little_endian := $(shell $(CC) -dM -E - </dev/null | \
				    grep 'define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__')
MENDIAN := $(if $(lib_bpf_is_little_endian),-mlittle-endian,-mbig-endian)

# Use BPF CPU v3 when Clang supports it. Otherwise use v2.
lib_bpf_clang_cpu := $(shell $(CLANG) --target=bpf -mcpu=help 2>&1 | \
			     grep -q 'v3' && echo v3 || echo v2)

# Accept anonymous struct and union members in vmlinux.h.
BPF_CFLAGS = -g -Wall -Werror -D__TARGET_ARCH_$(SRCARCH) $(MENDIAN)	\
	     -I$(INCLUDE_DIR) -I$(APIDIR)				\
	     -std=gnu11							\
	     -fno-strict-aliasing					\
	     -fms-extensions -Wno-microsoft-anon-tag			\
	     -Wno-compare-distinct-pointer-types			\
	     $(CLANG_SYS_INCLUDES) $(BPF_EXTRA_CFLAGS)

# $1 = source, $2 = object. -MMD -MP tracks non-system headers.
define lib_bpf_build_rule
	$(call msg,CLNG-BPF,,$2)
	$(Q)$(CLANG) $(BPF_CFLAGS) -O2 --target=bpf -mcpu=$(lib_bpf_clang_cpu) \
		-MMD -MP -c $1 -o $2
endef

# ---- output folders -------------------------------------------------------
BPF_OBJ_DIR  ?= $(OUTPUT)
BPF_SKEL_DIR ?= $(OUTPUT)
# Reject empty directories before cleanup globs can reach the filesystem root.
ifeq ($(strip $(BPF_OBJ_DIR)),)
$(error lib.bpf.mk: BPF_OBJ_DIR is empty; set it after "include ../lib.mk")
endif
ifeq ($(strip $(BPF_SKEL_DIR)),)
$(error lib.bpf.mk: BPF_SKEL_DIR is empty; set it after "include ../lib.mk")
endif

# ---- build folders --------------------------------------------------------
lib_bpf_make_dirs := $(sort $(lib_bpf_build_dir)/libbpf			\
			    $(lib_bpf_host_build_dir)/libbpf		\
			    $(lib_bpf_host_build_dir)/bpftool		\
			    $(lib_bpf_include_dir)			\
			    $(filter-out $(OUTPUT),$(BPF_OBJ_DIR) $(BPF_SKEL_DIR)))
$(lib_bpf_make_dirs):
	$(call msg,MKDIR,,$@)
	$(Q)mkdir -p $@

# ---- target libbpf --------------------------------------------------------
# Pass unexported toolchain settings and build PIC for PIE test binaries.
# libbpf consumes USERCFLAGS through EXTRA_CFLAGS.
$(BPFOBJ): $(lib_bpf_sources) $(lib_bpf_api_dir)/linux/bpf.h \
	   | $(lib_bpf_build_dir)/libbpf
	$(Q)$(MAKE) $(lib_bpf_submake_extras) -C $(lib_bpf_dir) \
		    OUTPUT=$(lib_bpf_build_dir)/libbpf/ \
		    ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) CC="$(CC)"     \
		    EXTRA_CFLAGS='-g $(OPT_FLAGS) -fPIC $(EXTRA_CFLAGS) $(USERCFLAGS)' \
		    DESTDIR=$(lib_bpf_scratch_dir) prefix= all install_headers

# ---- host libbpf, only when the target differs ----------------------------
ifneq ($(BPFOBJ),$(lib_bpf_host_obj))
$(lib_bpf_host_obj): $(lib_bpf_sources) $(lib_bpf_api_dir)/linux/bpf.h \
		| $(lib_bpf_host_build_dir)/libbpf
	$(Q)$(MAKE) $(lib_bpf_submake_extras) -C $(lib_bpf_dir) \
		    ARCH= CROSS_COMPILE= \
		    OUTPUT=$(lib_bpf_host_build_dir)/libbpf/ \
		    CC="$(HOSTCC)" LD="$(HOSTLD)" \
		    EXTRA_CFLAGS='-g $(OPT_FLAGS) $(EXTRA_CFLAGS)' \
		    DESTDIR=$(lib_bpf_host_scratch_dir) prefix= all install_headers
endif

# ---- host bpftool ---------------------------------------------------------
$(DEFAULT_BPFTOOL): $(wildcard $(lib_bpf_bpftool_dir)/*.[ch] \
				 $(lib_bpf_bpftool_dir)/Makefile) \
		    $(lib_bpf_host_obj) | $(lib_bpf_host_build_dir)/bpftool
	$(Q)$(MAKE) $(lib_bpf_submake_extras) -C $(lib_bpf_bpftool_dir) \
		    ARCH= CROSS_COMPILE= CC="$(HOSTCC)" LD="$(HOSTLD)" \
		    EXTRA_CFLAGS='-g $(OPT_FLAGS) $(EXTRA_CFLAGS) $(lib_bpf_host_user_cflags)' \
		    EXTRA_LDFLAGS='$(EXTRA_LDFLAGS)'		  \
		    OUTPUT=$(lib_bpf_host_build_dir)/bpftool/	  \
		    LIBBPF_OUTPUT=$(lib_bpf_host_build_dir)/libbpf/ \
		    LIBBPF_DESTDIR=$(lib_bpf_host_scratch_dir)/	  \
		    prefix= DESTDIR=$(lib_bpf_host_scratch_dir)/ install-bin

# ---- build vmlinux.h ------------------------------------------------------
lib_bpf_vmlinux_h     := $(INCLUDE_DIR)/vmlinux.h
lib_bpf_vmlinux_stamp := $(INCLUDE_DIR)/vmlinux.h.stamp

# Preserve vmlinux.h's timestamp when its contents do not change.
ifeq ($(wildcard $(lib_bpf_vmlinux_h)),)
# Regenerate if the header is missing but its stamp remains.
.PHONY: $(lib_bpf_vmlinux_stamp)
endif

# Use a normal edge so dependents see a changed header in the same make run.
$(lib_bpf_vmlinux_h): $(lib_bpf_vmlinux_stamp) ;

$(lib_bpf_vmlinux_stamp): $(lib_bpf_vmlinux_deps) | $(INCLUDE_DIR)
ifeq ($(VMLINUX_H),)
	$(call msg,GEN,,$(lib_bpf_vmlinux_h))
	$(Q)test -n "$(VMLINUX_BTF)" || { \
		echo "lib.bpf.mk: no vmlinux at any of \"$(VMLINUX_BTF_PATHS)\"" >&2; \
		exit 1; }
	$(Q)$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@.tmp
else
	$(call msg,CP,,$(lib_bpf_vmlinux_h))
	$(Q)cp "$(VMLINUX_H)" $@.tmp
endif
	$(Q)cmp -s $@.tmp $(lib_bpf_vmlinux_h) || mv $@.tmp $(lib_bpf_vmlinux_h)
	$(Q)rm -f $@.tmp
	$(Q)touch $@

# ---- BPF objects and skeletons --------------------------------------------
BPF_PROG_EXT ?= .bpf.c
# Each source must end with BPF_PROG_EXT so Make can remove that ending.
lib_bpf_bad_srcs := $(filter-out %$(BPF_PROG_EXT),$(BPF_SRCS))
ifneq ($(lib_bpf_bad_srcs),)
$(error lib.bpf.mk: BPF_SRCS entries must end in $(BPF_PROG_EXT): $(lib_bpf_bad_srcs))
endif
lib_bpf_stems := $(patsubst %$(BPF_PROG_EXT),%,$(notdir $(BPF_SRCS)))
# The stem becomes the skeleton's C name; reject dots and hyphens.
lib_bpf_bad_stems := $(strip $(foreach s,$(lib_bpf_stems),			\
			$(if $(findstring .,$(s))$(findstring -,$(s)),$(s))))
ifneq ($(lib_bpf_bad_stems),)
$(error lib.bpf.mk: BPF_SRCS basenames must not contain '.' or '-': $(lib_bpf_bad_stems))
endif
# Output names omit directories, so reject duplicate stems.
ifneq ($(words $(lib_bpf_stems)),$(words $(sort $(lib_bpf_stems))))
$(error lib.bpf.mk: BPF_SRCS has colliding basenames: $(BPF_SRCS))
endif
BPF_SKEL_EXT    ?= .skel.h
lib_bpf_subskel_ext := $(patsubst %skel.h,%subskel.h,$(BPF_SKEL_EXT))
# Keep skeleton suffixes distinct and cleanup globs narrow.
ifeq ($(lib_bpf_subskel_ext),$(BPF_SKEL_EXT))
$(error lib.bpf.mk: BPF_SKEL_EXT must end in skel.h: $(BPF_SKEL_EXT))
endif
BPF_OBJS  := $(addprefix $(BPF_OBJ_DIR)/,$(addsuffix .bpf.o,$(lib_bpf_stems)))
BPF_SKELS := $(addprefix $(BPF_SKEL_DIR)/,$(addsuffix $(BPF_SKEL_EXT),$(lib_bpf_stems)))
ifneq ($(BPF_GEN_SUBSKEL),)
BPF_SUBSKELS := $(addprefix $(BPF_SKEL_DIR)/,$(addsuffix $(lib_bpf_subskel_ext),$(lib_bpf_stems)))
endif

# Use per-source rules to avoid changing normal .c lookup.
# Track source headers before BPFOBJ installs their updated copies.
define lib_bpf_obj_rule
$(BPF_OBJ_DIR)/$(patsubst %$(BPF_PROG_EXT),%,$(notdir $(1))).bpf.o: $(1)	\
		$(BPF_EXTRA_HDRS) $(lib_bpf_header_sources)			\
		$(INCLUDE_DIR)/vmlinux.h | $(BPF_OBJ_DIR) $(BPFOBJ)
	$$(call lib_bpf_build_rule,$$<,$$@)
endef
$(foreach src,$(BPF_SRCS),$(eval $(call lib_bpf_obj_rule,$(src))))

# Generate both headers together so either missing target rebuilds the pair.
lib_bpf_skel_targets := $(BPF_SKEL_DIR)/%$(BPF_SKEL_EXT)
ifneq ($(BPF_GEN_SUBSKEL),)
lib_bpf_skel_targets += $(BPF_SKEL_DIR)/%$(lib_bpf_subskel_ext)
endif

# Link three times and require the final two objects to match.
$(lib_bpf_skel_targets): $(BPF_OBJ_DIR)/%.bpf.o $(BPFTOOL) | $(BPF_SKEL_DIR)
	$(call msg,GEN-SKEL,,$(BPF_SKEL_DIR)/$*$(BPF_SKEL_EXT))
	$(Q)$(BPFTOOL) gen object $(<:.o=.linked1.o) $<
	$(Q)$(BPFTOOL) gen object $(<:.o=.linked2.o) $(<:.o=.linked1.o)
	$(Q)$(BPFTOOL) gen object $(<:.o=.linked3.o) $(<:.o=.linked2.o)
	$(Q)diff $(<:.o=.linked2.o) $(<:.o=.linked3.o)
	$(Q)$(BPFTOOL) gen skeleton $(<:.o=.linked3.o) name $* > $(BPF_SKEL_DIR)/$*$(BPF_SKEL_EXT)
ifneq ($(BPF_GEN_SUBSKEL),)
	$(Q)$(BPFTOOL) gen subskeleton $(<:.o=.linked3.o) name $* > $(BPF_SKEL_DIR)/$*$(lib_bpf_subskel_ext)
endif
	$(Q)rm -f $(<:.o=.linked1.o) $(<:.o=.linked2.o) $(<:.o=.linked3.o)

# Read the header dependencies written by -MMD.
-include $(BPF_OBJS:.o=.d)

# ---- values for the test Makefile -----------------------------------------
# Add the installed libbpf/vmlinux.h directory and the skeleton directory.
CFLAGS += -I$(INCLUDE_DIR) -I$(BPF_SKEL_DIR)

# Add target zstd when found by the target pkg-config.
PKG_CONFIG ?= $(CROSS_COMPILE)pkg-config
BPF_LDLIBS := $(BPFOBJ) -lelf -lz
ifneq ($(shell $(PKG_CONFIG) --exists libzstd 2>/dev/null && echo y),)
BPF_LDLIBS += -lzstd
endif

# Add skeletons after lib.mk defines all.
all: $(BPF_SKELS) $(BPF_SUBSKELS)

# The skeleton already embeds each BPF object in the test binary. To install the
# objects separately, add TEST_GEN_FILES += $(BPF_OBJS).

# $1 = binary, $2 = test source. Use the same compile and link flags as lib.mk.
define bpf_link
	$(call msg,BINARY,,$1)
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(TARGET_ARCH) $2 \
		$(BPF_LDLIBS) $(LDLIBS) -o $1
endef

EXTRA_CLEAN += $(sort $(lib_bpf_scratch_dir) $(lib_bpf_host_scratch_dir)) \
	       $(addprefix $(BPF_OBJ_DIR)/,*.bpf.o *.bpf.d *.linked*.o)	\
	       $(addprefix $(BPF_SKEL_DIR)/,*$(BPF_SKEL_EXT) *$(lib_bpf_subskel_ext))
