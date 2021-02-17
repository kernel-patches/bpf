# SPDX-License-Identifier: GPL-2.0

# Rules to convert a .h file to inline RST documentation

SRC_DIR = $(srctree)/Documentation/bpf
PARSER = $(srctree)/scripts/bpf_doc.py
UAPI = $(srctree)/include/uapi/linux

TARGETS = $(BUILDDIR)/bpf/bpf_syscall.rst

$(BUILDDIR)/bpf/bpf_syscall.rst: $(UAPI)/bpf.h
	$(PARSER) syscall > $@

.PHONY: all html epub xml latex linkcheck clean

all: $(IMGDOT) $(BUILDDIR)/bpf $(TARGETS)

html: all
epub: all
xml: all
latex: $(IMGPDF) all
linkcheck:

clean:
	-rm -f -- $(TARGETS) 2>/dev/null

$(BUILDDIR)/bpf:
	$(Q)mkdir -p $@
