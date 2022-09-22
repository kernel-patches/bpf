# SPDX-License-Identifier: GPL-2.0
#
# Rules to convert BPF program types in tools/lib/bpf/libbpf.c
# into a .csv file

PROGRAM_TYPES = $(srctree)/Documentation/bpf/libbpf/program_types.csv

TARGETS := $(PROGRAM_TYPES)


$(PROGRAM_TYPES):	$(srctree)/tools/lib/bpf/libbpf.c
	$(Q)$(srctree)/scripts/gen-bpf-progtypes.sh $< $@

.PHONY: all html epub xml latex linkcheck clean

all: $(BUILDDIR) ${TARGETS}
	@:

html: all
epub: all
xml: all
latex: all
linkcheck:

clean:
	-$(Q)rm -f ${TARGETS} 2>/dev/null

$(BUILDDIR):
	$(Q)mkdir -p $@
