# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2020 Intel Corporation.

CFLAGS += -O2 -g -std=gnu99 -Wall -I../../../../usr/include/

XSKDIR := $(realpath ./xdpprogs)
XSKOBJ := xdpxceiver

TEST_PROGS := TEST_PREREQUISITES.sh \
	TEST_XSK_SKB_NOPOLL.sh \
	TEST_XSK_SKB_POLL.sh \
	TEST_XSK_DRV_NOPOLL.sh \
	TEST_XSK_DRV_POLL.sh \
	TEST_XSK_SKB_TEARDOWN.sh \
	TEST_XSK_DRV_TEARDOWN.sh
TEST_FILES := prereqs.sh xskenv.sh
TEST_TRANSIENT_FILES := veth.spec
TEST_PROGS_EXTENDED := $(XSKDIR)/$(XSKOBJ)

all: $(TEST_PROGS_EXTENDED)

KSFT_KHDR_INSTALL := 1
include ../lib.mk

$(TEST_PROGS_EXTENDED): $(XSKDIR)/$(XSKOBJ)

$(XSKDIR)/$(XSKOBJ):
	cd $(XSKDIR) && $(MAKE)

override define CLEAN
	cd $(XSKDIR) && $(MAKE) clean
endef
