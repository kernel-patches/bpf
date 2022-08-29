# SPDX-License-Identifier: GPL-2.0
#
# Rules to convert BPF program types in tools/lib/bpf/libbpf.c
# into a .csv file

FILES = program_types.csv

TARGETS := $(addprefix $(BUILDDIR)/, $(FILES))

# Extract program types and properties from the section definitions in libbpf.c such as
# SEC_DEF("socket", SOCKET_FILTER, 0, SEC_NONE) to generate program_types.csv
#
# Here is a sample of the generated output that includes .rst formatting:
#
#  Program Type,Attach Type,ELF Section Name,Sleepable
#  ``BPF_PROG_TYPE_SOCKET_FILTER``,,``socket``,
#  ``BPF_PROG_TYPE_SK_REUSEPORT``,``BPF_SK_REUSEPORT_SELECT_OR_MIGRATE``,``sk_reuseport/migrate``,
#  ``BPF_PROG_TYPE_SK_REUSEPORT``,``BPF_SK_REUSEPORT_SELECT``,``sk_reuseport``,
#  ``BPF_PROG_TYPE_KPROBE``,,``kprobe+``,
#  ``BPF_PROG_TYPE_KPROBE``,,``uprobe+``,
#  ``BPF_PROG_TYPE_KPROBE``,,``uprobe.s+``,Yes

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
