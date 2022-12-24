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
TEST_GEN_PROGS += test_match
TEST_GEN_PROGS += test_xt_udp
TEST_GEN_PROGS += test_target
TEST_GEN_PROGS += test_rule
TEST_GEN_PROGS += test_codegen

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
BPFILTER_MATCH_SRCS := $(BPFILTERSRCDIR)/match.c $(BPFILTERSRCDIR)/xt_udp.c
BPFILTER_TARGET_SRCS := $(BPFILTERSRCDIR)/target.c
BPFILTER_RULE_SRCS := $(BPFILTERSRCDIR)/rule.c

BPFILTER_COMMON_SRCS := $(BPFILTER_MAP_SRCS) $(BPFILTER_CODEGEN_SRCS)
BPFILTER_COMMON_SRCS += $(BPFILTERSRCDIR)/context.c $(BPFILTERSRCDIR)/logger.c
BPFILTER_COMMON_SRCS += $(BPFILTER_MATCH_SRCS) $(BPFILTER_TARGET_SRCS)
BPFILTER_COMMON_SRCS += $(BPFILTER_RULE_SRCS) $(BPFILTERSRCDIR)/table.c
BPFILTER_COMMON_SRCS +=  $(BPFILTERSRCDIR)/filter-table.c $(BPFILTERSRCDIR)/sockopt.c

$(OUTPUT)/test_map: test_map.c $(BPFILTER_MAP_SRCS)
$(OUTPUT)/test_match: test_match.c $(BPFILTER_COMMON_SRCS)
$(OUTPUT)/test_xt_udp: test_xt_udp.c $(BPFILTER_COMMON_SRCS)
$(OUTPUT)/test_target: test_target.c $(BPFILTER_COMMON_SRCS)
$(OUTPUT)/test_rule: test_rule.c $(BPFILTER_COMMON_SRCS)
$(OUTPUT)/test_codegen: test_codegen.c $(BPFILTER_COMMON_SRCS)
