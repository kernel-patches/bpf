// SPDX-License-Identifier: GPL-2.0
//
// Copyright (C) 2025, 2026 Red Hat, Inc

#include "template.c"

SEC("fentry.s/kexec_image_parser_anchor")
__attribute__((used)) int BPF_PROG(parse_pe, struct kexec_context *context,
				unsigned long parser_id)
{
	return 0;
}
