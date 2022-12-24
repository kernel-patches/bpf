# SPDX-License-Identifier: GPL-2.0

top_srcdir = ../../../../..
TOOLSDIR := $(abspath ../../../../)
TOOLSINCDIR := $(TOOLSDIR)/include
APIDIR := $(TOOLSINCDIR)/uapi
BPFILTERSRCDIR := $(top_srcdir)/net/bpfilter
LIBDIR := $(TOOLSDIR)/lib
BPFDIR := $(LIBDIR)/bpf

CFLAGS += -Wall -g -pthread -I$(TOOLSINCDIR) -I$(APIDIR) -I$(BPFILTERSRCDIR)

TEST_GEN_PROGS += test_map

KSFT_KHDR_INSTALL := 1

include ../../lib.mk

SCRATCH_DIR := $(OUTPUT)/tools
BUILD_DIR := $(SCRATCH_DIR)/build
BPFOBJ_DIR := $(BUILD_DIR)/libbpf
BPFOBJ := $(BPFOBJ_DIR)/libbpf.a

MAKE_DIRS := $(BPFOBJ_DIR)
$(MAKE_DIRS):
	$(call msg,MKDIR,,$@)
	$(Q)mkdir -p $@

$(BPFOBJ): $(wildcard $(BPFDIR)/*.[ch] $(BPFDIR)/Makefile)			\
	   ../../../../include/uapi/linux/bpf.h					\
	   | $(INCLUDE_DIR) $(BUILD_DIR)/libbpf
	$(Q)$(MAKE) $(submake_extras) -C $(BPFDIR) OUTPUT=$(BUILD_DIR)/libbpf/ 	\
		    DESTDIR=$(SCRATCH_DIR) prefix= all install_headers

BPFILTER_MAP_SRCS := $(BPFILTERSRCDIR)/map-common.c
BPFILTER_CODEGEN_SRCS := $(BPFILTERSRCDIR)/codegen.c $(BPFOBJ) -lelf -lz

$(OUTPUT)/test_map: test_map.c $(BPFILTER_MAP_SRCS)
