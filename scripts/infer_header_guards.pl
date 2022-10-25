#!/usr/bin/env perl
# SPDX-License-Identifier: GPL-2.0

# This script scans the passed directory for header files (files ending with ".h").
# For each header file it tries to infer the name of a C pre-processor
# variable used as a double include guard (dubbed as "header guard").
# For example:
#
#   #ifdef __MY_HEADER__  // <-- "header guard"
#     ...
#   #endif
#
# The inferred guards are printed to stdout in the following format:
#
#   <header-file> <header-guard>
#
# This is an expected format for pahole --header_guards_db parameter.
# Intended usage is to infer header guards for Linux UAPI headers.
# The collected information is further used in BTF embedded into kernel.
#
# The following inference logic is used for each file:
# - find all pairs `#ifndef <name> #define <name>`
# - if there is a unique <name> that matches a pattern - use this
#   <name> as a header guard, (see subroutine `select_guard` for the
#   list of the patterns);
# - files containing only #include directives are safe to ignore.
#
# There are a few UAPI header files that don't fit in such logic,
# header guards for these files are hard-coded in %OVERRIDES hash.
#
# The script reports inference only when --report-failures flag is
# passed. This flag is intended for BPF tests.
#
# See subroutine `help` for usage info.

use strict;
use warnings;
use File::Basename;
use File::Find;
use Getopt::Long;

sub help {
	my $message = << "EOM";
Usage:
  $0 [--report-failures] directory-or-file...
  $0 --help

For a specific file or for each .h file in a directory infer the name
of a C pre-processor variable used as a double include guard.

Options:
  --report-failures   Report inference errors to stderr,
                      exit with non-zero code if guards were not inferred
                      for some files.
  --help              Print this message and exit.
EOM
	print $message;
}

my %OVERRIDES = (
	# Header guards that don't follow common naming rules
	"include/uapi/linux/cciss_ioctl.h" => "_UAPICCISS_IOCTLH",
	"include/uapi/linux/hpet.h" => "_UAPI__HPET__",
	"include/uapi/linux/if_ppp.h" => "_PPP_IOCTL_H",
	"include/uapi/linux/netfilter/xt_NFLOG.h" => "_XT_NFLOG_TARGET",
	"include/uapi/linux/netfilter_ipv6/ip6t_NPT.h" => "__NETFILTER_IP6T_NPT",
	"include/uapi/linux/quota.h" => "_UAPI_LINUX_QUOTA_",
	"include/uapi/linux/v4l2-common.h" => "__V4L2_COMMON__",
	# Headers that should be ignored
	"arch/x86/include/uapi/asm/hw_breakpoint.h" => undef,
	"arch/x86/include/uapi/asm/posix_types.h" => undef,
	"arch/x86/include/uapi/asm/setup.h" => undef,
	"include/generated/uapi/linux/version.h" => undef,
	"include/uapi/asm-generic/bitsperlong.h" => undef,
	"include/uapi/asm-generic/kvm_para.h" => undef,
	"include/uapi/asm-generic/unistd.h" => undef,
	"include/uapi/linux/irqnr.h" => undef,
	"include/uapi/linux/zorro_ids.h" => undef,
	);

sub get_basename {
	my ($filename) = @_;
	my $basename = fileparse($filename, qr/\.[^.]*/);
	return $basename;
}

sub find_bracket_candidates {
	my ($filename) = @_;
	my @candidates = ();
	my $guard_candidate = undef;
	my $safe_to_ignore = 1;

	open my $file, $filename or die "Can't open file $filename: $!";
	while (my $line = <$file>) {
		if (not($line =~ "^#include")) {
			$safe_to_ignore = 0;
		}
		if ($line =~ "^#ifndef[ \t]+([a-zA-Z0-9_]+)") {
			$guard_candidate = $1;
		} elsif ($guard_candidate && $line =~ "^#define[ \t]+${guard_candidate}") {
			push(@candidates, $guard_candidate);
			$guard_candidate = undef;
		}
	}
	close $file;

	return ($safe_to_ignore, @candidates);
}

sub select_guard {
	my ($filename, @candidates) = @_;
	my $basename = get_basename($filename);
	my @regexes = ("$basename.*_H(EADER)?",
		       "_H(EADER)?_",
		       "_H(EADER)?\$");
	foreach my $re (@regexes) {
		my @filtered = grep(/$re/i, @candidates);
		if (scalar(@filtered) == 1) {
			return $filtered[0];
		}
	}

	return undef;
}

sub collect_headers {
	my ($dir) = @_;
	my @headers = ();

	find(sub { /\.h$/ && push(@headers, $File::Find::name); }, $dir);

	return @headers;
}

my $report_failures = 0;
my $options_parsed = GetOptions(
	"report-failures" => \$report_failures,
	"help" => sub { help(); exit 0; },
    );

if (!$options_parsed || scalar @ARGV == 0) {
	help();
	exit 1;
}

my @headers;

foreach my $dir_or_file (@ARGV) {
	if (-f $dir_or_file) {
		push(@headers, $dir_or_file);
	} elsif (-d $dir_or_file) {
		push(@headers, collect_headers($dir_or_file));
	} else {
		print("'$dir_or_file' is not a file or directory.\n");
		help();
		exit 1;
	}
}

my $rc = 0;

foreach my $header (@headers) {
	my $basename = get_basename($header);
	my $guard;

	if (exists $OVERRIDES{$header}) {
		$guard = $OVERRIDES{$basename};
	} else {
		my ($safe_to_ignore, @candidates) = find_bracket_candidates($header);
		$guard = select_guard($header, @candidates);
		if ((not $guard) && (not $safe_to_ignore) && $report_failures) {
			print STDERR "Can't select guard for $header, candidates:\n";
			print STDERR "  ";
			if (scalar(@candidates)) {
				print STDERR join(", ", @candidates);
			} else {
				print STDERR "<no candidates>"
			}
			print STDERR "\n";
			$rc = 1;
		}
	}
	if ($guard) {
		# Remove the _UAPI prefix/suffix the same way
		# scripts/headers_install.sh does it.
		$guard =~ s/_UAPI//;
		print("$header $guard\n");
	}
}

exit $rc;
