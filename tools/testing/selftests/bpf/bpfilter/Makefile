# SPDX-License-Identifier: GPL-2.0

top_srcdir = ../../../../..
TOOLSDIR := $(abspath ../../../../)
TOOLSINCDIR := $(TOOLSDIR)/include
APIDIR := $(TOOLSINCDIR)/uapi
BPFILTERSRCDIR := $(top_srcdir)/net/bpfilter

CFLAGS += -Wall -g -pthread -I$(TOOLSINCDIR) -I$(APIDIR) -I$(BPFILTERSRCDIR)

TEST_GEN_PROGS += test_map

KSFT_KHDR_INSTALL := 1

include ../../lib.mk

BPFILTER_MAP_SRCS := $(BPFILTERSRCDIR)/map-common.c

$(OUTPUT)/test_map: test_map.c $(BPFILTER_MAP_SRCS)
