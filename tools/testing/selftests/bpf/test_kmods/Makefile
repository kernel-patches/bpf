TEST_KMOD_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
KDIR ?= $(abspath $(TEST_KMOD_DIR)/../../../../..)

ifeq ($(V),1)
Q =
else
Q = @
endif

MODULES = bpf_testmod.ko bpf_test_no_cfi.ko

$(foreach m,$(MODULES),$(eval obj-m += $(m:.ko=.o)))

CFLAGS_bpf_testmod.o = -I$(src)

all: modules.built

modules.built: *.[ch]
	+$(Q)make -C $(KDIR) M=$(TEST_KMOD_DIR) modules
	touch modules.built

clean:
	+$(Q)make -C $(KDIR) M=$(TEST_KMOD_DIR) clean
	rm -f modules.built

