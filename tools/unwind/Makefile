# SPDX-License-Identifier: GPL-2.0-only OR MIT
include ../scripts/Makefile.include

bindir ?= /usr/bin

ifeq ($(srctree),)
srctree := $(patsubst %/,%,$(dir $(CURDIR)))
srctree := $(patsubst %/,%,$(dir $(srctree)))
endif

ifneq ($(LLVM),)
  $(call allow-override,HOSTCXX,$(LLVM_PREFIX)clang++$(LLVM_SUFFIX))
else
  $(call allow-override,HOSTCXX,g++)
endif

# verify_cfi is a host analysis tool; ensure feature checks probe the host
# compiler even when CROSS_COMPILE is set in the environment.
CC  := $(HOSTCC)
CXX := $(HOSTCXX)

# Auto-discover versioned llvm-config (e.g. Debian/Ubuntu llvm-config-21) when
# the default unversioned binary is absent, and export it for Makefile.feature.
ifeq ($(shell command -v $(firstword $(LLVM_CONFIG)) >/dev/null 2>&1 && echo y),)
  LLVM_CONFIG_CANDIDATES := llvm-config-22 llvm-config-21 llvm-config-20 \
			    llvm-config-19 llvm-config-18
  FOUND_LLVM_CONFIG := $(firstword $(foreach c,$(LLVM_CONFIG_CANDIDATES), \
			 $(if $(shell command -v $(c) >/dev/null 2>&1 && echo y),$(c))))
  ifneq ($(FOUND_LLVM_CONFIG),)
    LLVM_CONFIG := $(FOUND_LLVM_CONFIG)
  endif
endif
export LLVM_CONFIG

FEATURE_USER := .verify_cfi
FEATURE_TESTS := llvm
FEATURE_DISPLAY := llvm

check_feat := 1
NON_CHECK_FEAT_TARGETS := clean
ifdef MAKECMDGOALS
ifeq ($(filter-out $(NON_CHECK_FEAT_TARGETS),$(MAKECMDGOALS)),)
  check_feat := 0
endif
endif
ifeq ($(SKIP_LLVM),1)
  check_feat := 0
endif

ifeq ($(check_feat),1)
ifeq ($(FEATURES_DUMP),)
include $(srctree)/tools/build/Makefile.feature
else
include $(FEATURES_DUMP)
endif
endif

LLVM_COMPONENTS := debuginfodwarf object mc mcdisassembler all-targets support

ifeq ($(feature-llvm),1)
ifneq ($(SKIP_LLVM),1)
  LLVM_INCDIR := $(shell $(LLVM_CONFIG) --includedir 2>/dev/null)
  ifneq ($(wildcard $(LLVM_INCDIR)/llvm/DebugInfo/DWARF/LowLevel/DWARFUnwindTable.h),)
    HAS_LIBLLVM := 1
    LLVM_CXXFLAGS := $(filter-out -D_GNU_SOURCE -std=%,$(shell $(LLVM_CONFIG) --cxxflags 2>/dev/null))
    LLVM_LDFLAGS  := $(shell $(LLVM_CONFIG) --ldflags 2>/dev/null)
    LLVM_LIBS     := $(shell $(LLVM_CONFIG) --link-shared --libs $(LLVM_COMPONENTS) 2>/dev/null)
    ifeq ($(LLVM_LIBS),)
      LLVM_LIBS   := $(shell $(LLVM_CONFIG) --libs $(LLVM_COMPONENTS) 2>/dev/null) \
		     $(shell $(LLVM_CONFIG) --system-libs $(LLVM_COMPONENTS) 2>/dev/null)
    endif
  endif
endif
endif

TOOLS_INCLUDES := -I$(srctree)/tools/include -I$(srctree)/tools/include/uapi \
		  -I$(srctree)/tools/arch/x86/include

SHIM_CFLAGS := -O2 -g -Wall -Wextra -Wno-unused-parameter -Wno-maybe-uninitialized \
	$(TOOLS_INCLUDES)

VERIFY_CXXFLAGS := -O2 -g -Wall -Wextra -std=gnu++20 $(LLVM_CXXFLAGS) -DHAVE_VERIFY_INSN \
	-I$(CURDIR) $(TOOLS_INCLUDES) $(CXXFLAGS)
VERIFY_LDFLAGS  := $(LLVM_LDFLAGS) $(LDFLAGS)

KERNEL_CFI_DEPS := $(srctree)/kernel/unwind/dwarf_cfi.c \
		   $(srctree)/tools/include/linux/unwind_dwarf_cfi.h

VERIFY_OBJS := $(OUTPUT)dwarf_cfi_host.o \
		 $(OUTPUT)verify_cfi.o \
		 $(OUTPUT)verify_insn_arch.o \
		 $(OUTPUT)verify_insn.o

ifeq ($(HAS_LIBLLVM),1)
all: $(OUTPUT)verify_cfi
else
all:
ifeq ($(REQUIRE_LLVM),1)
	$(error libLLVM 17+ development headers/libraries not found (LLVM_CONFIG=$(LLVM_CONFIG)))
else
	@echo "  SKIP    verify_cfi (libLLVM dev files not found; set LLVM_CONFIG=...)"
endif
endif

$(OUTPUT)dwarf_cfi_host.o: dwarf_cfi_host.c dwarf_cfi_host.h $(KERNEL_CFI_DEPS)
	$(QUIET_CC)$(HOSTCC) $(SHIM_CFLAGS) -c $< -o $@

$(OUTPUT)%.o: %.cpp $(wildcard *.hpp) dwarf_cfi_host.h
	$(QUIET_CXX)$(HOSTCXX) $(VERIFY_CXXFLAGS) -c $< -o $@

$(OUTPUT)verify_cfi: $(VERIFY_OBJS)
	$(QUIET_LINK)$(HOSTCXX) $(VERIFY_CXXFLAGS) $(VERIFY_OBJS) \
		-o $@ $(VERIFY_LDFLAGS) $(LLVM_LIBS)

install: all
	@if [ -x "$(OUTPUT)verify_cfi" ]; then \
		install -d -m 755 $(DESTDIR)$(bindir); \
		install $(OUTPUT)verify_cfi $(DESTDIR)$(bindir); \
	fi

clean:
	$(RM) -r $(OUTPUT)*.o $(OUTPUT)verify_cfi \
		$(OUTPUT)feature $(OUTPUT)FEATURE-DUMP*

.PHONY: all install clean
