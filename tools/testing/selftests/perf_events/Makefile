# SPDX-License-Identifier: GPL-2.0
CFLAGS += -Wl,-no-as-needed -Wall $(KHDR_INCLUDES)
LDFLAGS += -lpthread

TEST_GEN_PROGS := sigtrap_threads remove_on_exec watermark_signal mmap unwind_user_cfi
include ../lib.mk

$(OUTPUT)/unwind_user_cfi: CFLAGS += $(TOOLS_INCLUDES) -O2 -fomit-frame-pointer -fasynchronous-unwind-tables
