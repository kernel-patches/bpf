# SPDX-License-Identifier: GPL-2.0-only
include ../../scripts/Makefile.include
include ../../scripts/Makefile.arch

srctree := $(abspath $(CURDIR)/../../../)

ifeq ($(V),1)
  Q =
  msg =
else
  Q = @
  ifeq ($(silent),1)
    msg =
  else
    msg = @printf '  %-8s %s%s\n' "$(1)" "$(notdir $(2))" "$(if $(3), $(3))";
  endif
  MAKEFLAGS=--no-print-directory
endif

RM      ?= rm

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
SUBCMD_INCLUDE := $(SUBCMD_DESTDIR)include

BINARY     := $(OUTPUT)/resolve_btfids
BINARY_IN  := $(BINARY)-in.o

LIBELF_FLAGS := $(shell $(HOSTPKG_CONFIG) libelf --cflags 2>/dev/null)
LIBELF_LIBS  := $(shell $(HOSTPKG_CONFIG) libelf --libs 2>/dev/null || echo -lelf)

RESOLVE_BTFIDS_CFLAGS = -g \
          -I$(srctree)/tools/include \
          -I$(srctree)/tools/include/uapi \
          -I$(LIBBPF_INCLUDE) \
          -I$(SUBCMD_INCLUDE) \
          $(LIBELF_FLAGS)

# Overrides for the prepare step libraries.
HOST_OVERRIDES_PREPARE := AR="$(HOSTAR)" CC="$(HOSTCC)" LD="$(HOSTLD)" \
	  ARCH="$(HOSTARCH)" CROSS_COMPILE=""

# Overrides for Makefile.build C targets.
HOST_OVERRIDES_BUILD := $(HOST_OVERRIDES_PREPARE) \
	  CFLAGS="$(HOSTCFLAGS) $(KBUILD_HOSTCFLAGS) $(RESOLVE_BTFIDS_CFLAGS)" \

LIBS = $(LIBELF_LIBS) -lz

all: $(BINARY)

export srctree OUTPUT Q
include $(srctree)/tools/build/Makefile.include

prepare: $(BPFOBJ) $(SUBCMDOBJ)

$(OUTPUT) $(OUTPUT)/libsubcmd $(LIBBPF_OUT):
	$(call msg,MKDIR,,$@)
	$(Q)mkdir -p $(@)

$(SUBCMDOBJ): fixdep FORCE | $(OUTPUT)/libsubcmd
	$(Q)$(MAKE) -C $(SUBCMD_SRC) OUTPUT=$(SUBCMD_OUT) \
		    DESTDIR=$(SUBCMD_DESTDIR) $(HOST_OVERRIDES_PREPARE) prefix= subdir= \
		    $(abspath $@) install_headers

$(BPFOBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(LIBBPF_OUT)
	$(Q)$(MAKE) $(submake_extras) -C $(LIBBPF_SRC) OUTPUT=$(LIBBPF_OUT)    \
		    DESTDIR=$(LIBBPF_DESTDIR) $(HOST_OVERRIDES_PREPARE) prefix= subdir= \
		    $(abspath $@) install_headers

$(BINARY_IN): fixdep FORCE prepare | $(OUTPUT)
	$(Q)$(MAKE) $(build)=resolve_btfids $(HOST_OVERRIDES_BUILD)

$(BINARY): $(BPFOBJ) $(SUBCMDOBJ) $(BINARY_IN)
	$(call msg,LINK,$@)
	$(Q)$(HOSTCC) $(BINARY_IN) $(KBUILD_HOSTLDFLAGS) -o $@ $(BPFOBJ) $(SUBCMDOBJ) $(LIBS)

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
