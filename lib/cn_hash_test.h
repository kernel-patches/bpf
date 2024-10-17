/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2024 Oracle and/or its affiliates.
 * Author: Anjali Kulkarni <anjali.k.kulkarni@oracle.com>
 */
int cn_display_hlist(pid_t pid, int max_len, int *hkey, int *key_display);
int cn_add_elem(__u32 uexit_code, pid_t pid);
int cn_del_get_exval(pid_t pid);
int cn_get_exval(pid_t pid);
bool cn_table_empty(void);
