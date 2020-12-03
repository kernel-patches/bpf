// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Google

int x = 0;

int foo(void)
{
	return __sync_val_compare_and_swap(&x, 1, 2);
}
