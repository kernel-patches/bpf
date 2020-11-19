BPF_SIDECAR_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
KDIR ?= $(abspath $(BPF_SIDECAR_DIR)/../../../../..)

ifeq ($(V),1)
Q =
else
Q = @
endif

MODULES = bpf_sidecar.ko

obj-m += bpf_sidecar.o
CFLAGS_bpf_sidecar.o = -I$(src)

all:
	+$(Q)make -C $(KDIR) M=$(BPF_SIDECAR_DIR) modules

clean:
	+$(Q)make -C $(KDIR) M=$(BPF_SIDECAR_DIR) clean

