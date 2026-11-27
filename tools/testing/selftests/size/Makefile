# SPDX-License-Identifier: GPL-2.0-only
CFLAGS = -Os -static -nostdlib -nostdinc -ffreestanding -fno-stack-protector -s
CFLAGS += -isystem $(top_srcdir)/tools/include/nolibc $(KHDR_INCLUDES)

TEST_GEN_PROGS := get_size

include ../lib.mk

CC_IS_GCC := $(shell printf '\043if defined(__GNUC__) && !defined(__clang__)\nGCC\n\043endif\n' | \
	$(CC) $(CFLAGS) -E -P -x c - 2>/dev/null)
LDLIBS += $(if $(filter GCC,$(CC_IS_GCC)),-lgcc)

$(OUTPUT)/get_size: | headers
