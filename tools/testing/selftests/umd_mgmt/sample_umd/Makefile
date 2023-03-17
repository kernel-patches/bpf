KDIR ?= ../../../../..

userprogs := sample_umh
sample_umh-objs := sample_handler.o
userccflags += -I $(srctree)

$(obj)/sample_binary_blob.o: $(obj)/sample_umh

MODULES = sample_loader_kmod.ko sample_mgr.ko

obj-m += sample_loader_kmod.o sample_mgr.o

sample_loader_kmod-objs = sample_loader.o sample_binary_blob.o

all:
	+$(Q)$(MAKE) -C $(KDIR) M=$$PWD modules

clean:
	+$(Q)$(MAKE) -C $(KDIR) M=$$PWD clean

install: all
	+$(Q)$(MAKE) -C $(KDIR) M=$$PWD modules_install
