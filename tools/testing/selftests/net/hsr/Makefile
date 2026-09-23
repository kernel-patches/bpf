# SPDX-License-Identifier: GPL-2.0

top_srcdir = ../../../../..

CFLAGS += -Wall -Wl,--no-as-needed -O2 -g

TEST_PROGS := \
	hsr_ping.sh \
	hsr_prp_redbox.sh \
	hsr_redbox.sh \
	link_faults.sh \
	prp_ping.sh \
	hsr_ptp.sh \
# end of TEST_PROGS

TEST_FILES += hsr_common.sh

TEST_GEN_FILES := hsr_ptp_test

include ../../lib.mk
