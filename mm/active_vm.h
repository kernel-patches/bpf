/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MM_ACTIVE_VM_H
#define __MM_ACTIVE_VM_H

#ifdef CONFIG_ACTIVE_VM
extern struct page_ext_operations active_vm_ops;
#endif /* CONFIG_ACTIVE_VM */
#endif /* __MM_ACTIVE_VM_H */
