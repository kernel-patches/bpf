BPF_TEST_MODORDER_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
KDIR ?= $(abspath $(BPF_TEST_MODORDER_DIR)/../../../../..)

ifeq ($(V),1)
Q =
else
Q = @
endif

MODULES = bpf_test_modorder_x.ko bpf_test_modorder_y.ko

obj-m += bpf_test_modorder_x.o bpf_test_modorder_y.o

all:
	+$(Q)make -C $(KDIR) M=$(BPF_TEST_MODORDER_DIR) modules

clean:
	+$(Q)make -C $(KDIR) M=$(BPF_TEST_MODORDER_DIR) clean

