# SPDX-License-Identifier: GPL-2.0

top_srcdir = ../../../../..
TOOLSDIR := $(abspath ../../../../)
TOOLSINCDIR := $(TOOLSDIR)/include
APIDIR := $(TOOLSINCDIR)/uapi
BPFILTERSRCDIR := $(top_srcdir)/net/bpfilter

CFLAGS += -Wall -g -pthread -I$(TOOLSINCDIR) -I$(APIDIR) -I$(BPFILTERSRCDIR)

TEST_GEN_PROGS += test_io
TEST_GEN_PROGS += test_map
TEST_GEN_PROGS += test_match
TEST_GEN_PROGS += test_target

KSFT_KHDR_INSTALL := 1

include ../../lib.mk

$(OUTPUT)/test_io: test_io.c $(BPFILTERSRCDIR)/io.c
$(OUTPUT)/test_map: test_map.c $(BPFILTERSRCDIR)/map-common.c
$(OUTPUT)/test_match: test_match.c $(BPFILTERSRCDIR)/match.c $(BPFILTERSRCDIR)/map-common.c \
	$(BPFILTERSRCDIR)/context.c $(BPFILTERSRCDIR)/bflog.c $(BPFILTERSRCDIR)/target.c
$(OUTPUT)/test_target: test_target.c $(BPFILTERSRCDIR)/target.c $(BPFILTERSRCDIR)/map-common.c \
	$(BPFILTERSRCDIR)/context.c $(BPFILTERSRCDIR)/bflog.c $(BPFILTERSRCDIR)/match.c
