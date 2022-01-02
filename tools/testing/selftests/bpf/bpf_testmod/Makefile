BPF_TESTMOD_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
KDIR ?= $(abspath $(BPF_TESTMOD_DIR)/../../../../..)

ifeq ($(V),1)
Q =
else
Q = @
endif

MODULES = bpf_testmod.ko bpf_mod_kfunc_race.ko

obj-m += bpf_testmod.o bpf_mod_kfunc_race.o
CFLAGS_bpf_testmod.o = -I$(src)
CFLAGS_bpf_mod_kfunc_race.o = -I$(src)

all:
	+$(Q)make -C $(KDIR) M=$(BPF_TESTMOD_DIR) modules

clean:
	+$(Q)make -C $(KDIR) M=$(BPF_TESTMOD_DIR) clean

