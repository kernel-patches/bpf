# SPDX-License-Identifier: GPL-2.0
KERNEL="../../../.."

CFLAGS += -Wall $(KHDR_INCLUDES) -I $(KERNEL)/include/uapi -I $(KERNEL)/include

proc_filter: proc_filter.o
	cc proc_filter.o -o proc_filter

proc_filter.o: proc_filter.c
	cc -c proc_filter.c -o proc_filter.o $(CFLAGS)

thread: thread.o thread_filter.o
	cc thread.o thread_filter.o -o thread

thread.o: thread.c $(DEPS)
		cc -c thread.c -o thread.o $(CFLAGS)

thread_filter.o: thread_filter.c
		cc -c thread_filter.c -o thread_filter.o $(CFLAGS)

define EXTRA_CLEAN
	rm *.o thread
endef

TEST_GEN_PROGS = proc_filter

include ../lib.mk
