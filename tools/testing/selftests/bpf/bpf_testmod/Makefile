BPF_TESTMOD_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
KDIR ?= $(abspath $(BPF_TESTMOD_DIR)/../../../../..)

ifeq ($(V),1)
Q =
else
Q = @
endif

MODULES = bpf_testmod.ko bpf_testmod_standalone.ko

obj-m				+=	bpf_testmod.o
obj-m				+=	bpf_testmod_standalone.o

CFLAGS_bpf_testmod.o = -I$(src)
CFLAGS_bpf_testmod_standalone.o += -I$(src)

all:
	+$(Q)make -C $(KDIR) M=$(BPF_TESTMOD_DIR) bpf_testmod.ko
	+$(Q)make -C $(KDIR) BTF_BASE= M=$(BPF_TESTMOD_DIR) bpf_testmod_standalone.ko

clean:
	+$(Q)make -C $(KDIR) M=$(BPF_TESTMOD_DIR) clean

