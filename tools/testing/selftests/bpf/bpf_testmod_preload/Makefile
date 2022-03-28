BPF_TESTMOD_PRELOAD_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
KDIR ?= $(abspath $(BPF_TESTMOD_PRELOAD_DIR)/../../../../..)

ifeq ($(V),1)
Q =
else
Q = @
endif

MODULES = bpf_testmod_preload.ko

obj-m += bpf_testmod_preload.o
CFLAGS_bpf_testmod_preload.o = -I$(BPF_TESTMOD_PRELOAD_DIR)/../tools/include

all:
	+$(Q)make -C $(KDIR) M=$(BPF_TESTMOD_PRELOAD_DIR) modules

clean:
	+$(Q)make -C $(KDIR) M=$(BPF_TESTMOD_PRELOAD_DIR) clean

