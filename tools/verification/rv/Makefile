# SPDX-License-Identifier: GPL-2.0-only

ifeq ($(srctree),)
  srctree	:= $(patsubst %/,%,$(dir $(CURDIR)))
  srctree	:= $(patsubst %/,%,$(dir $(srctree)))
  srctree	:= $(patsubst %/,%,$(dir $(srctree)))
endif

include $(srctree)/tools/scripts/Makefile.include

# O is an alias for OUTPUT
OUTPUT          := $(O)

ifeq ($(OUTPUT),)
  OUTPUT       := $(CURDIR)/
else
  # subdir is used by the ../Makefile in $(call descend,)
  ifneq ($(subdir),)
    OUTPUT        := $(OUTPUT)/$(subdir)
  endif
endif

ifneq ($(patsubst %/,,$(lastword $(OUTPUT))),)
  OUTPUT := $(OUTPUT)/
endif

RV		:= $(OUTPUT)rv
RV_IN		:= $(RV)-in.o

VERSION		:= $(shell sh -c "make -sC ../../.. kernelversion | grep -v make")
DOCSRC		:= ../../../Documentation/tools/rv/

FEATURE_TESTS	:= libtraceevent
FEATURE_TESTS	+= libtracefs
FEATURE_TESTS	+= libbpf
FEATURE_TESTS	+= clang-bpf-co-re
FEATURE_TESTS	+= bpftool-btf
FEATURE_DISPLAY	:= libtraceevent
FEATURE_DISPLAY	+= libtracefs
FEATURE_DISPLAY	+= libbpf
FEATURE_DISPLAY	+= clang-bpf-co-re
FEATURE_DISPLAY	+= bpftool-btf

all: $(RV)

include $(srctree)/tools/build/Makefile.include
include Makefile.rv

# check for dependencies only on required targets
NON_CONFIG_TARGETS := clean install doc doc_clean doc_install bpf

config		:= 1
ifdef MAKECMDGOALS
  ifeq ($(filter-out $(NON_CONFIG_TARGETS),$(MAKECMDGOALS)),)
  config	:= 0
endif
endif

ifeq ($(config),1)
  include $(srctree)/tools/build/Makefile.feature
  include Makefile.config
endif

CFLAGS		+= $(INCLUDES) $(LIB_INCLUDES)

export CFLAGS OUTPUT srctree BUILD_BPF

$(RV): $(RV_IN)
	$(QUIET_LINK)$(CC) $(LDFLAGS) -o $(RV) $(RV_IN) $(EXTLIBS)

static: $(RV_IN)
	$(eval LDFLAGS += -static)
	$(QUIET_LINK)$(CC) $(LDFLAGS) -o $(RV)-static $(RV_IN) $(EXTLIBS)

BPF_DIR		:= bpf_monitors
BPF_REACT_DIR   := bpf_reactors
BPF_SOURCES	:= $(wildcard $(BPF_DIR)/*.c)
BPF_OBJECTS	:= $(BPF_SOURCES:.c=.o)
BPF_REACT_SOURCES := $(wildcard $(BPF_REACT_DIR)/*.c)
BPF_REACT_OBJECTS := $(BPF_REACT_SOURCES:.c=.o)
VMLINUX_H	:= $(BPF_DIR)/vmlinux.h

BPF_INCLUDES	:= -I$(srctree)/include/uapi
BPF_INCLUDES	+= -I$(srctree)/include
BPF_INCLUDES	+= -I$(BPF_DIR)

BPF_CFLAGS	:= -g -O2 -target bpf -MMD -MP $(BPF_INCLUDES)
BPF_CFLAGS	+= -Wall -Wno-unused-function -Wno-missing-declarations

VMLINUX		:= ../../../vmlinux
VMLINUX_BTF	?= $(if $(wildcard $(VMLINUX)) , $(VMLINUX), /sys/kernel/btf/vmlinux)

$(VMLINUX_H): $(VMLINUX_BTF)
	$(QUIET_GEN)$(SYSTEM_BPFTOOL) btf dump file $< format c > $@

$(BPF_DIR)/%.o: $(BPF_DIR)/%.c $(VMLINUX_H)
	$(QUIET_CLANG)$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(Q)$(LLVM_STRIP) -g $@
	$(Q)$(LLVM_OBJCOPY) --remove-section=.rel.rodata $@

$(BPF_REACT_DIR)/%.o: $(BPF_REACT_DIR)/%.c $(VMLINUX_H)
	$(QUIET_CLANG)$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(Q)$(LLVM_STRIP) -g $@
	$(Q)$(LLVM_OBJCOPY) --remove-section=.rel.rodata $@

-include $(BPF_SOURCES:.c=.d) $(BPF_REACT_SOURCES:.c=.d)

bpf: $(BPF_OBJECTS) $(BPF_REACT_OBJECTS)

rv.%: fixdep FORCE
	make -f $(srctree)/tools/build/Makefile.build dir=. $@

$(RV_IN): fixdep FORCE
	make $(build)=rv

ifeq ($(BUILD_BPF_OBJS),1)
all: bpf
endif

clean: doc_clean fixdep-clean
	$(call QUIET_CLEAN, rv)
	$(Q)find . -name '*.o' -delete -o -name '\.*.cmd' -delete -o -name '*.d' -delete
	$(Q)rm -f rv rv-static fixdep FEATURE-DUMP rv-*
	$(Q)rm -f $(VMLINUX_H)
	$(Q)rm -rf feature

check: $(RV)
	RV=$(RV) prove -o --directives -f tests/

.PHONY: FORCE clean check bpf
