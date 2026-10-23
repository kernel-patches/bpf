// SPDX-License-Identifier: GPL-2.0

__attribute__((noinline, visibility("default")))
int uprobe_multi_stripped_func(void)
{
	return 42;
}
