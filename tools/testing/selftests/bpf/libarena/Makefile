.PHONY: clean

LIBARENA=$(abspath .)


LIBARENA_SOURCES = $(wildcard $(LIBARENA)/src/*.bpf.c) $(wildcard $(LIBARENA)/selftests/*.bpf.c)
LIBARENA_OBJECTS = $(notdir $(LIBARENA_SOURCES:.bpf.c=.bpf.o))
LIBARENA_OBJECTS_ASAN = $(notdir $(LIBARENA_SOURCES:.bpf.c=_asan.bpf.o))

INCLUDES = -I$(LIBARENA)/include -I$(LIBARENA)/..
ifneq ($(INCLUDE_DIR),)
INCLUDES += -I$(INCLUDE_DIR)
endif
ifneq ($(LIBBPF_INCLUDE),)
INCLUDES += -I$(LIBBPF_INCLUDE)
endif

ASAN_FLAGS = -fsanitize=kernel-address -fno-stack-protector -fno-builtin
ASAN_FLAGS += -mllvm -asan-instrument-address-spaces=1 -mllvm -asan-shadow-addr-space=1
ASAN_FLAGS += -mllvm -asan-use-stack-safety=0 -mllvm -asan-stack=0
ASAN_FLAGS += -mllvm -asan-kernel=1
ASAN_FLAGS += -mllvm -asan-constructor-kind=none
ASAN_FLAGS += -mllvm -asan-destructor-kind=none

# ENABLE_ATOMICS_TESTS required because we use arena spinlocks
override BPF_CFLAGS += -DENABLE_ATOMICS_TESTS
override BPF_CFLAGS += -O2 -Wno-incompatible-pointer-types-discards-qualifiers
override BPF_CFLAGS += $(INCLUDES)

CFLAGS = -O2 -no-pie
CFLAGS += $(INCLUDES)

vpath %.bpf.c $(LIBARENA)/src $(LIBARENA)/selftests
vpath %.c $(LIBARENA)/src $(LIBARENA)/selftests

test_libarena_asan: selftest.c $(BPFOBJ) selftest_asan.skel.h
	$(call msg,BINARY,libarena,$@)
	$(Q)$(CLANG) $(LDLIBS) $(CFLAGS) -DBPF_ARENA_ASAN $< $(BPFOBJ) -o $@

test_libarena: selftest.c $(BPFOBJ) selftest.skel.h
	$(call msg,BINARY,libarena,$@)
	$(Q)$(CLANG) $(LDLIBS) $(CFLAGS) $< $(BPFOBJ) -o $@

selftest_asan.skel.h: main_asan.bpf.o
	$(call msg,GEN-SKEL,libarena,$@)
	$(Q)$(BPFTOOL) gen skeleton $< name "selftest_asan" > $@

selftest.skel.h: main.bpf.o
	$(call msg,GEN-SKEL,libarena,$@)
	$(Q)$(BPFTOOL) gen skeleton $< name "selftest" > $@

main_asan.bpf.o: $(LIBARENA_OBJECTS_ASAN)
	$(call msg,GEN-OBJ,libarena,$@)
	$(Q)$(BPFTOOL) gen object $@ $^

main.bpf.o: $(LIBARENA_OBJECTS)
	$(call msg,GEN-OBJ,libarena,$@)
	$(Q)$(BPFTOOL) gen object $@ $^

%_asan.bpf.o: %.bpf.c
	$(call msg,CLNG-BPF,libarena,$@)
	$(Q)$(CLANG) $(BPF_CFLAGS) $(ASAN_FLAGS) -DBPF_ARENA_ASAN $(BPF_TARGET_ENDIAN) -c $< -mcpu=v3 -o $@

%.bpf.o: %.bpf.c
	$(call msg,CLNG-BPF,libarena,$@)
	$(Q)$(CLANG) $(BPF_CFLAGS) $(BPF_TARGET_ENDIAN) -c $< -o $@

clean:
	$(Q)rm -f *.skel.h *.bpf.o test_libarena test_libarena_asan
