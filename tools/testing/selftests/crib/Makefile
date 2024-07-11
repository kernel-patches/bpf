# SPDX-License-Identifier: GPL-2.0
include ../../../build/Build.include
include ../../../scripts/Makefile.arch
include ../../../scripts/Makefile.include
include ../lib.mk

CUR_DIR := $(abspath .)
REPO_ROOT := $(abspath ../../../..)
TOOLS_DIR := $(REPO_ROOT)/tools
TOOLSINC_DIR := $(TOOLS_DIR)/include
BPFTOOL_DIR := $(TOOLS_DIR)/bpf/bpftool
UAPI_DIR := $(TOOLSINC_DIR)/uapi
LIB_DIR := $(TOOLS_DIR)/lib
LIBBPF_DIR := $(LIB_DIR)/bpf
GEN_DIR := $(REPO_ROOT)/include/generated
GEN_HDR := $(GEN_DIR)/autoconf.h

OUTPUT_DIR := $(CUR_DIR)/build
INCLUDE_DIR := $(OUTPUT_DIR)/include
SBIN_DIR:= $(OUTPUT_DIR)/sbin
OBJ_DIR := $(OUTPUT_DIR)/obj
CRIBOBJ_DIR := $(OBJ_DIR)/crib
LIBBPF_OUTPUT := $(OBJ_DIR)/libbpf/libbpf.a
LIBBPF_OBJ_DIR := $(OBJ_DIR)/libbpf
LIBBPF_OBJ := $(LIBBPF_OBJ_DIR)/libbpf.a

DEFAULT_BPFTOOL := $(SBIN_DIR)/bpftool
BPFTOOL ?= $(DEFAULT_BPFTOOL)

VMLINUX_BTF_PATHS ?= ../../../../vmlinux					\
		     /sys/kernel/btf/vmlinux					\
		     /boot/vmlinux-$(shell uname -r)
VMLINUX_BTF ?= $(abspath $(firstword $(wildcard $(VMLINUX_BTF_PATHS))))
ifeq ($(VMLINUX_BTF),)
$(error Cannot find a vmlinux for VMLINUX_BTF at any of "$(VMLINUX_BTF_PATHS)")
endif

ifneq ($(wildcard $(GEN_HDR)),)
  GENFLAGS := -DHAVE_GENHDR
endif

CFLAGS += -g -O2 -rdynamic -pthread -Wall -Werror $(GENFLAGS)		\
	  -I$(INCLUDE_DIR) -I$(GEN_DIR) -I$(LIB_DIR)			\
	  -I$(TOOLSINC_DIR) -I$(UAPI_DIR) -I$(CUR_DIR)/include		\
	  -Wno-unused-command-line-argument

LDFLAGS = -lelf -lz

IS_LITTLE_ENDIAN = $(shell $(CC) -dM -E - </dev/null |				\
			grep 'define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__')

define get_sys_includes
$(shell $(1) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }') \
$(shell $(1) -dM -E - </dev/null | grep '__riscv_xlen ' | awk '{printf("-D__riscv_xlen=%d -D__BITS_PER_LONG=%d", $$3, $$3)}')
endef

BPF_CFLAGS = -g -D__TARGET_ARCH_$(SRCARCH)				\
	     $(if $(IS_LITTLE_ENDIAN),-mlittle-endian,-mbig-endian)	\
	     -I$(CUR_DIR)/include -I$(CUR_DIR)/include/bpf-compat	\
	     -I$(INCLUDE_DIR) -I$(UAPI_DIR) 				\
	     -I$(REPO_ROOT)/include					\
	     $(call get_sys_includes,$(CLANG))				\
	     -Wall -Wno-compare-distinct-pointer-types			\
	     -Wno-incompatible-function-pointer-types			\
	     -O2 -mcpu=v3

MAKE_DIRS := $(sort $(OBJ_DIR)/libbpf $(OBJ_DIR)/libbpf			\
	     $(OBJ_DIR)/bpftool $(OBJ_DIR)/resolve_btfids		\
	     $(INCLUDE_DIR) $(CRIBOBJ_DIR) $(SBIN_DIR))

TEST_GEN_BPF_PROGS_SKEL := $(foreach prog,$(wildcard *.bpf.c),$(INCLUDE_DIR)/$(patsubst %.c,%.skel.h,$(prog)))

TEST_GEN_PROGS := $(addprefix $(SBIN_DIR)/, $(basename $(filter-out $(wildcard *.bpf.c), $(wildcard *.c))))

TEST_GEN_PROGS_OBJ := $(addsuffix .o,$(addprefix $(CRIBOBJ_DIR)/, $(notdir $(TEST_GEN_PROGS))))

$(MAKE_DIRS):
	$(call msg,MKDIR,,$@)
	$(Q)mkdir -p $@

$(LIBBPF_OBJ): $(wildcard $(LIBBPF_DIR)/*.[ch] $(LIBBPF_DIR)/Makefile)			\
	       $(UAPI_DIR)/linux/bpf.h							\
	       | $(OBJ_DIR)/libbpf
	$(Q)$(MAKE) $(submake_extras) -C $(LIBBPF_DIR) OUTPUT=$(OBJ_DIR)/libbpf/	\
		    EXTRA_CFLAGS='-g -O0 -fPIC'						\
		    DESTDIR=$(OUTPUT_DIR) prefix= all install_headers

$(DEFAULT_BPFTOOL): $(wildcard $(BPFTOOL_DIR)/*.[ch] $(BPFTOOL_DIR)/Makefile)	\
		    $(LIBBPF_OUTPUT) | $(OBJ_DIR)/bpftool
	$(Q)$(MAKE) $(submake_extras)  -C $(BPFTOOL_DIR)			\
		    ARCH= CROSS_COMPILE= CC=$(HOSTCC) LD=$(HOSTLD)		\
		    EXTRA_CFLAGS='-g -O0'					\
		    OUTPUT=$(OBJ_DIR)/bpftool/					\
		    LIBBPF_OUTPUT=$(OBJ_DIR)/libbpf/				\
		    LIBBPF_DESTDIR=$(OUTPUT_DIR)/				\
		    prefix= DESTDIR=$(OUTPUT_DIR)/ install-bin

$(INCLUDE_DIR)/vmlinux.h: $(VMLINUX_BTF) $(BPFTOOL) | $(INCLUDE_DIR)
ifeq ($(VMLINUX_H),)
	$(call msg,GEN,,$@)
	$(Q)$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@
else
	$(call msg,CP,,$@)
	$(Q)cp "$(VMLINUX_H)" $@
endif

$(CRIBOBJ_DIR)/%.bpf.o: %.bpf.c %.h $(INCLUDE_DIR)/vmlinux.h | $(LIBBPF_OBJ) $(CRIBOBJ_DIR)
	$(call msg,CLANG-BPF,,$(notdir $@))
	$(Q)$(CLANG) $(BPF_CFLAGS) -target bpf -c $< -o $@

$(INCLUDE_DIR)/%.bpf.skel.h: $(CRIBOBJ_DIR)/%.bpf.o $(INCLUDE_DIR)/vmlinux.h $(BPFTOOL) | $(INCLUDE_DIR)
	$(call msg,GEN-SKEL,,$(notdir $@))
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(TEST_GEN_PROGS_OBJ): $(CRIBOBJ_DIR)/%.o: %.c %.h $(INCLUDE_DIR)/%.bpf.skel.h | $(CRIBOBJ_DIR)
	$(call msg,CLANG,,$(notdir $@))
	$(Q)$(CLANG) $(CFLAGS) -c $< -o $@

$(TEST_GEN_PROGS): $(SBIN_DIR)/%: $(CRIBOBJ_DIR)/%.o $(LIBBPF_OBJ) | $(SBIN_DIR)
	$(call msg,CLANG-LINK,,$(notdir $@))
	$(Q)$(CLANG) $(CFLAGS) $(LDFLAGS) $^ -o $@

override define CLEAN
	rm -rf $(OUTPUT_DIR)
endef

all: $(TEST_GEN_PROGS)

.PHONY: all clean help

.DEFAULT_GOAL := all

.DELETE_ON_ERROR:

.SECONDARY:
