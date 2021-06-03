# SPDX-License-Identifier: GPL-2.0

top_srcdir = ../../../../..
TOOLSDIR := $(abspath ../../../../)
TOOLSINCDIR := $(TOOLSDIR)/include
APIDIR := $(TOOLSINCDIR)/uapi
BPFILTERSRCDIR := $(top_srcdir)/net/bpfilter

CFLAGS += -Wall -g -pthread -I$(TOOLSINCDIR) -I$(APIDIR) -I$(BPFILTERSRCDIR)

TEST_GEN_PROGS += test_map
TEST_GEN_PROGS += test_match
TEST_GEN_PROGS += test_target
TEST_GEN_PROGS += test_rule

KSFT_KHDR_INSTALL := 1

include ../../lib.mk

BPFILTER_MATCH_SRCS := $(BPFILTERSRCDIR)/match.c $(BPFILTERSRCDIR)/xt_udp.c
BPFILTER_TARGET_SRCS := $(BPFILTERSRCDIR)/target.c

BPFILTER_COMMON_SRCS := $(BPFILTERSRCDIR)/map-common.c $(BPFILTERSRCDIR)/context.c \
	$(BPFILTERSRCDIR)/rule.c $(BPFILTERSRCDIR)/table.c
BPFILTER_COMMON_SRCS += $(BPFILTER_MATCH_SRCS) $(BPFILTER_TARGET_SRCS)

$(OUTPUT)/test_map: test_map.c $(BPFILTERSRCDIR)/map-common.c
$(OUTPUT)/test_match: test_match.c $(BPFILTER_COMMON_SRCS)
$(OUTPUT)/test_target: test_target.c $(BPFILTER_COMMON_SRCS)
$(OUTPUT)/test_rule: test_rule.c $(BPFILTER_COMMON_SRCS)
