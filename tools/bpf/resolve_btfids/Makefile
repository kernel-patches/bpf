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
HOSTCC  ?= gcc
HOSTLD  ?= ld
HOSTAR  ?= ar
HOSTPKG_CONFIG ?= pkg-config
CROSS_COMPILE =

# If OUTPUT was inherited from a parent build's command line (e.g. from
# kselftest), it points to the wrong directory and may lack a trailing
# slash.  The tools/build Makefile.build concatenates $(OUTPUT) with
# filenames without a separating slash ($(OUTPUT)%.o), so a missing
# trailing '/' produces corrupted paths such as "mmmain.o" instead of
# "mm/main.o", and the linker cannot find resolve_btfids-in.o.
#
# When built via the kernel build system, OUTPUT is set by
# scripts/Makefile.include (origin "file") from the O= parameter, which
# is correct.  Only a command-line origin indicates leakage from a
# parent build and needs to be reset.  Both "command line" and
# "environment" origins indicate leakage; "file" (set by Makefile.include
# from O=) and "undefined" are legitimate and must not be overridden.
ifneq ($(filter command line environment,$(origin OUTPUT)),)
override OUTPUT := $(srctree)/tools/bpf/resolve_btfids/
endif
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

export srctree OUTPUT HOSTCFLAGS_resolve_btfids Q HOSTCC HOSTLD HOSTAR
include $(srctree)/tools/build/Makefile.include

$(BINARY_IN): fixdep FORCE prepare | $(OUTPUT)
	$(Q)$(MAKE) $(build)=resolve_btfids

$(BINARY): $(BPFOBJ) $(SUBCMDOBJ) $(BINARY_IN)
	$(call msg,LINK,$@)
	$(Q)$(HOSTCC) $(BINARY_IN) $(KBUILD_HOSTLDFLAGS) $(EXTRA_LDFLAGS) -o $@ $(BPFOBJ) $(SUBCMDOBJ) $(LIBS)

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
