SOCK_ADDR_TEST_MOD_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
KDIR ?= $(abspath $(SOCK_ADDR_TEST_MOD_DIR)/../../../../..)

ifeq ($(V),1)
Q =
else
Q = @
endif

MODULES = sock_addr_testmod.ko

obj-m += sock_addr_testmod.o
CFLAGS_sock_addr_testmod.o = -I$(src)

all:
	+$(Q)make -C $(KDIR) M=$(SOCK_ADDR_TEST_MOD_DIR) modules

clean:
	+$(Q)make -C $(KDIR) M=$(SOCK_ADDR_TEST_MOD_DIR) clean

