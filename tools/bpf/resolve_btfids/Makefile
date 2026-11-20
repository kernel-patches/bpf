# SPDX-License-Identifier: GPL-2.0-only
include ../../scripts/Makefile.include
include ../../scripts/Makefile.arch

srctree := $(abspath $(CURDIR)/../../../)

ifeq ($(V),1)
  msg =
else
  ifeq ($(silent),1)
    msg =
  else
    msg = @printf '  %-8s %s%s\n' "$(1)" "$(notdir $(2))" "$(if $(3), $(3))";
  endif
  MAKEFLAGS=--no-print-directory
endif

# Overrides for the prepare step libraries.
HOST_OVERRIDES := AR="$(HOSTAR)" CC="$(HOSTCC)" LD="$(HOSTLD)" ARCH="$(HOSTARCH)" \
		  CROSS_COMPILE="" CLANG_CROSS_FLAGS="" EXTRA_CFLAGS="$(HOSTCFLAGS)"

RM      ?= rm
HOSTPKG_CONFIG ?= pkg-config
CROSS_COMPILE =

OUTPUT ?= $(srctree)/tools/bpf/resolve_btfids/

LIBBPF_SRC := $(srctree)/tools/lib/bpf/
SUBCMD_SRC := $(srctree)/tools/lib/subcmd/

BPFOBJ     := $(OUTPUT)/libbpf/libbpf.a
LIBBPF_OUT := $(abspath $(dir $(BPFOBJ)))/
SUBCMDOBJ  := $(OUTPUT)/libsubcmd/libsubcmd.a
SUBCMD_OUT := $(abspath $(dir $(SUBCMDOBJ)))/

LIBBPF_DESTDIR := $(LIBBPF_OUT)
LIBBPF_INCLUDE := $(LIBBPF_DESTDIR)include

SUBCMD_DESTDIR := $(SUBCMD_OUT)

BINARY     := $(OUTPUT)/resolve_btfids
BINARY_IN  := $(BINARY)-in.o

all: $(BINARY)

prepare: $(BPFOBJ) $(SUBCMDOBJ)

$(OUTPUT) $(OUTPUT)/libsubcmd $(LIBBPF_OUT):
	$(call msg,MKDIR,,$@)
	$(Q)mkdir -p $(@)

$(SUBCMDOBJ): fixdep FORCE | $(OUTPUT)/libsubcmd
	$(Q)$(MAKE) -C $(SUBCMD_SRC) OUTPUT=$(SUBCMD_OUT) \
		    DESTDIR=$(SUBCMD_DESTDIR) $(HOST_OVERRIDES) prefix= subdir= \
		    $(abspath $@)

$(BPFOBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(LIBBPF_OUT)
	$(Q)$(MAKE) $(submake_extras) -C $(LIBBPF_SRC) OUTPUT=$(LIBBPF_OUT)    \
		    DESTDIR=$(LIBBPF_DESTDIR) $(HOST_OVERRIDES) prefix= subdir= \
		    $(abspath $@) install_headers

LIBELF_FLAGS := $(shell $(HOSTPKG_CONFIG) libelf --cflags 2>/dev/null)

ifneq ($(filter -static,$(EXTRA_LDFLAGS)),)
LIBELF_LIBS  := $(shell $(HOSTPKG_CONFIG) libelf --libs --static 2>/dev/null || echo -lelf -lzstd)
else
LIBELF_LIBS  := $(shell $(HOSTPKG_CONFIG) libelf --libs 2>/dev/null || echo -lelf)
endif

ZLIB_LIBS  := $(shell $(HOSTPKG_CONFIG) zlib --libs 2>/dev/null || echo -lz)

HOSTCFLAGS_resolve_btfids += -g \
          -I$(srctree)/tools/include \
          -I$(srctree)/tools/include/uapi \
          -I$(LIBBPF_INCLUDE) \
          -I$(srctree)/tools/lib \
          $(LIBELF_FLAGS) \
          -Wall -Werror

LIBS = $(LIBELF_LIBS) $(ZLIB_LIBS)

# text_mc.cpp reads machine code with LLVM's MC layer. Only --fmodret_scan needs
# it: don't touch LLVM unless kbuild is going to run the tool with that flag.
ifneq ($(filter --fmodret_scan,$(RESOLVE_BTFIDS_FLAGS)),)
LLVM_MC := y
HOSTCXX ?= g++
LLVM_MC_SH := LLVM_CONFIG="$(LLVM_CONFIG)" HOSTCXX="$(HOSTCXX)" \
	      $(SHELL) $(srctree)/tools/bpf/resolve_btfids/llvm-mc.sh $(SRCARCH)
# Kconfig knows from llvm-mc.sh that LLVM is installed. Whether text_mc.cpp can
# be built with it shows here.
LLVM_MC_HELP := CONFIG_BPF_FMODRET_SCAN=y needs a C++17 compiler (HOSTCXX=$(HOSTCXX)) and the \
		headers and libraries of LLVM 17 or later (LLVM_CONFIG=$(LLVM_CONFIG), packages \
		llvm-dev, llvm-devel). See above what is wrong, or switch the option off
or_llvm_mc_help := || { echo '$(LLVM_MC_HELP)' >&2; false; }
HOSTCFLAGS_resolve_btfids += -DHAVE_LLVM_MC
CXX := $(HOSTCXX)
CXXFLAGS := $(filter-out -Werror,$(HOSTCFLAGS_resolve_btfids)) -O2 \
	    $(or $(shell $(LLVM_MC_SH) cxxflags),$(error $(LLVM_MC_HELP)))
LIBS += $(or $(shell $(LLVM_MC_SH) libs),$(error $(LLVM_MC_HELP)))
endif

export srctree OUTPUT HOSTCFLAGS_resolve_btfids Q HOSTCC HOSTLD HOSTAR
export CXX CXXFLAGS SRCARCH LLVM_MC or_llvm_mc_help
include $(srctree)/tools/build/Makefile.include

$(BINARY_IN): fixdep FORCE prepare | $(OUTPUT)
	$(Q)$(MAKE) $(build)=resolve_btfids

$(BINARY): $(BPFOBJ) $(SUBCMDOBJ) $(BINARY_IN)
	$(call msg,LINK,$@)
	$(Q)$(HOSTCC) $(BINARY_IN) $(KBUILD_HOSTLDFLAGS) $(EXTRA_LDFLAGS) -o $@ $(BPFOBJ) $(SUBCMDOBJ) $(LIBS) $(or_llvm_mc_help)

clean_objects := $(wildcard $(OUTPUT)/*.o                \
                            $(OUTPUT)/.*.o.cmd           \
                            $(OUTPUT)/.*.o.d             \
                            $(LIBBPF_OUT)                \
                            $(LIBBPF_DESTDIR)            \
                            $(SUBCMD_OUT)                \
                            $(SUBCMD_DESTDIR)            \
                            $(OUTPUT)/resolve_btfids)

ifneq ($(clean_objects),)
clean: fixdep-clean
	$(call msg,CLEAN,$(BINARY))
	$(Q)$(RM) -rf $(clean_objects)
else
clean:
endif

tags:
	$(call msg,GEN,,tags)
	$(Q)ctags -R . $(LIBBPF_SRC) $(SUBCMD_SRC)

FORCE:

.PHONY: all FORCE clean tags prepare
