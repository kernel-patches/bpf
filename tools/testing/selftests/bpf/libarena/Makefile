.PHONY: clean

LIBARENA=$(abspath .)


LIBARENA_SOURCES = $(wildcard $(LIBARENA)/src/*.bpf.c) $(wildcard $(LIBARENA)/selftests/*.bpf.c)
LIBARENA_OBJECTS = $(notdir $(LIBARENA_SOURCES:.bpf.c=.bpf.o))

INCLUDES = -I$(LIBARENA)/include -I$(LIBARENA)/..
ifneq ($(INCLUDE_DIR),)
INCLUDES += -I$(INCLUDE_DIR)
endif
ifneq ($(LIBBPF_INCLUDE),)
INCLUDES += -I$(LIBBPF_INCLUDE)
endif

# ENABLE_ATOMICS_TESTS required because we use arena spinlocks
override BPF_CFLAGS += -DENABLE_ATOMICS_TESTS
override BPF_CFLAGS += -O2 -Wno-incompatible-pointer-types-discards-qualifiers
override BPF_CFLAGS += $(INCLUDES)

CFLAGS = -O2 -no-pie
CFLAGS += $(INCLUDES)

vpath %.bpf.c $(LIBARENA)/src $(LIBARENA)/selftests
vpath %.c $(LIBARENA)/src $(LIBARENA)/selftests

all: test_libarena

test_libarena: selftest.c $(BPFOBJ) selftest.skel.h
	$(call msg,BINARY,libarena,$@)
	$(Q)$(CLANG) $(LDLIBS) $(CFLAGS) $< $(BPFOBJ) -o $@

selftest.skel.h: main.bpf.o
	$(call msg,GEN-SKEL,libarena,$@)
	$(Q)$(BPFTOOL) gen skeleton $< name "selftest" > $@

main.bpf.o: $(LIBARENA_OBJECTS)
	$(call msg,GEN-OBJ,libarena,$@)
	$(Q)$(BPFTOOL) gen object $@ $^

%.bpf.o: %.bpf.c
	$(call msg,CLNG-BPF,libarena,$@)
	$(Q)$(CLANG) $(BPF_CFLAGS) $(BPF_TARGET_ENDIAN) -c $< -o $@

clean:
	$(Q)rm -f *.skel.h *.bpf.o test_libarena
