# SPDX-License-Identifier: GPL-2.0
#
# Rules to convert BPF program types in tools/lib/bpf/libbpf.c
# into a .csv file

FILES = program_types.csv

TARGETS := $(addprefix $(BUILDDIR)/, $(FILES))

$(BUILDDIR)/program_types.csv:	$(srctree)/tools/lib/bpf/libbpf.c
	$(Q)awk -F'[",[:space:]]+' \
	'BEGIN { print "Program Type,Attach Type,ELF Section Name,Sleepable" } \
	/SEC_DEF\(\"/ && !/SEC_DEPRECATED/ { \
	type = "``BPF_PROG_TYPE_" $$4 "``"; \
	attach = index($$5, "0") ? "" : "``" $$5 "``"; \
	section = "``" $$3 "``"; \
	sleepable = index($$0, "SEC_SLEEPABLE") ? "Yes" : ""; \
	print type "," attach "," section "," sleepable }' \
	$< > $@

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
