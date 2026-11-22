// SPDX-License-Identifier: GPL-2.0-only
/*
 * User-space Minimal DWARF CFI unwinding via ELF PT_GNU_EH_FRAME.
 */

#include <linux/elf.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mmap_lock.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/unwind_dwarf_cfi.h>
#include <linux/unwind_user.h>

#define USER_CFI_MAX_PHDRS	64U
#define USER_CFI_MAX_VMA_STEPS	8U

/**
 * parse_user_elf64_eh_hdr() - Locate PT_GNU_EH_FRAME in a 64-bit user ELF image
 * @elf_base: User virtual address of the mapped ELF64 header (file offset 0).
 * @hdr_uaddr: Output user virtual address of the PT_GNU_EH_FRAME segment.
 * @hdr_size: Output size in bytes of the PT_GNU_EH_FRAME segment.
 *
 * Reads the 64-bit ELF header and up to %USER_CFI_MAX_PHDRS program headers
 * from user memory, computes the mapping load bias from the file-offset-0
 * PT_LOAD segment, and resolves the runtime address of PT_GNU_EH_FRAME.
 * Must be called without holding mmap_lock because copy_from_user() may fault.
 *
 * Return: 0 on success, -ENOENT if no non-empty PT_GNU_EH_FRAME or base
 * PT_LOAD segment exists, -EINVAL if the ELF header is invalid, or -EFAULT on
 * an unmapped user read.
 */
static int parse_user_elf64_eh_hdr(unsigned long elf_base,
				   unsigned long *hdr_uaddr, size_t *hdr_size)
{
	Elf64_Ehdr ehdr;
	unsigned long load_bias = 0;
	bool have_load0 = false, have_eh = false;
	Elf64_Addr eh_vaddr = 0;
	Elf64_Xword eh_memsz = 0;
	unsigned int i;

	if (copy_from_user(&ehdr, (const void __user *)elf_base, sizeof(ehdr)))
		return -EFAULT;

	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
	    ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
	    ehdr.e_phentsize != sizeof(Elf64_Phdr) ||
	    !ehdr.e_phnum || ehdr.e_phnum > USER_CFI_MAX_PHDRS)
		return -EINVAL;

	for (i = 0; i < ehdr.e_phnum; i++) {
		Elf64_Phdr phdr;
		unsigned long p_addr = elf_base + ehdr.e_phoff +
				       (size_t)i * sizeof(phdr);

		if (copy_from_user(&phdr, (const void __user *)p_addr, sizeof(phdr)))
			return -EFAULT;

		if (phdr.p_type == PT_LOAD && !have_load0 && phdr.p_offset == 0) {
			load_bias = elf_base - ALIGN_DOWN(phdr.p_vaddr, PAGE_SIZE);
			have_load0 = true;
		} else if (phdr.p_type == PT_GNU_EH_FRAME) {
			eh_vaddr = phdr.p_vaddr;
			eh_memsz = phdr.p_memsz;
			have_eh = true;
		}
	}

	if (!have_load0 || !have_eh || !eh_memsz)
		return -ENOENT;

	*hdr_uaddr = load_bias + eh_vaddr;
	*hdr_size = (size_t)eh_memsz;
	return 0;
}

/**
 * parse_user_elf32_eh_hdr() - Locate PT_GNU_EH_FRAME in a 32-bit user ELF image
 * @elf_base: User virtual address of the mapped ELF32 header (file offset 0).
 * @hdr_uaddr: Output user virtual address of the PT_GNU_EH_FRAME segment.
 * @hdr_size: Output size in bytes of the PT_GNU_EH_FRAME segment.
 *
 * 32-bit compat counterpart to parse_user_elf64_eh_hdr(). Must be called
 * without holding mmap_lock.
 *
 * Return: 0 on success, -ENOENT if no non-empty PT_GNU_EH_FRAME or base
 * PT_LOAD segment exists, -EINVAL if the ELF header is invalid, or -EFAULT on
 * an unmapped user read.
 */
static int parse_user_elf32_eh_hdr(unsigned long elf_base,
				   unsigned long *hdr_uaddr, size_t *hdr_size)
{
	Elf32_Ehdr ehdr;
	unsigned long load_bias = 0;
	bool have_load0 = false, have_eh = false;
	Elf32_Addr eh_vaddr = 0;
	Elf32_Word eh_memsz = 0;
	unsigned int i;

	if (copy_from_user(&ehdr, (const void __user *)elf_base, sizeof(ehdr)))
		return -EFAULT;

	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
	    ehdr.e_ident[EI_CLASS] != ELFCLASS32 ||
	    ehdr.e_phentsize != sizeof(Elf32_Phdr) ||
	    !ehdr.e_phnum || ehdr.e_phnum > USER_CFI_MAX_PHDRS)
		return -EINVAL;

	for (i = 0; i < ehdr.e_phnum; i++) {
		Elf32_Phdr phdr;
		unsigned long p_addr = elf_base + ehdr.e_phoff +
				       (size_t)i * sizeof(phdr);

		if (copy_from_user(&phdr, (const void __user *)p_addr, sizeof(phdr)))
			return -EFAULT;

		if (phdr.p_type == PT_LOAD && !have_load0 && phdr.p_offset == 0) {
			load_bias = elf_base - ALIGN_DOWN((unsigned long)phdr.p_vaddr,
							  PAGE_SIZE);
			have_load0 = true;
		} else if (phdr.p_type == PT_GNU_EH_FRAME) {
			eh_vaddr = phdr.p_vaddr;
			eh_memsz = phdr.p_memsz;
			have_eh = true;
		}
	}

	if (!have_load0 || !have_eh || !eh_memsz)
		return -ENOENT;

	*hdr_uaddr = load_bias + eh_vaddr;
	*hdr_size = (size_t)eh_memsz;
	return 0;
}

/**
 * lookup_vma_elf_base_locked() - Find the ELF base mapping for an executable IP
 * @mm: Address space of the current user task (mmap_lock held for read).
 * @ip: User instruction pointer to resolve.
 * @vma_start: Output start address of the executable VMA containing @ip.
 * @vma_end: Output end address of the executable VMA containing @ip (left
 *           unchanged if @ip does not lie in an executable VMA).
 * @elf_base: Output start address of the file-offset-0 ELF header mapping.
 *
 * Modern linkers (-z separate-code) often place the ELF header in a preceding
 * read-only VMA at vm_pgoff == 0 while mapping .text into a separate VM_EXEC
 * VMA with vm_pgoff > 0. Walk up to %USER_CFI_MAX_VMA_STEPS preceding VMAs
 * backed by the same file to locate the vm_pgoff == 0 mapping, while also
 * supporting single-VMA binaries and special mappings such as [vdso].
 *
 * Return: true if an ELF base mapping was found and stored in *@elf_base,
 * false otherwise.
 */
static bool lookup_vma_elf_base_locked(struct mm_struct *mm, unsigned long ip,
				       unsigned long *vma_start,
				       unsigned long *vma_end,
				       unsigned long *elf_base)
{
	struct vm_area_struct *vma = vma_lookup(mm, ip);
	struct vm_area_struct *prev;
	struct file *target_file;
	unsigned int steps = 0;

	if (!vma || !(vma->vm_flags & VM_EXEC))
		return false;

	*vma_start = vma->vm_start;
	*vma_end = vma->vm_end;

	if (vma_is_anonymous(vma) || !vma->vm_file) {
		if (vma->vm_pgoff == 0) {
			/* Special mappings such as [vdso] */
			*elf_base = vma->vm_start;
			return true;
		}
		return false;
	}

	if (vma->vm_pgoff == 0) {
		*elf_base = vma->vm_start;
		return true;
	}

	target_file = vma->vm_file;
	{
		VMA_ITERATOR(vmi, mm, vma->vm_start);

		while (steps++ < USER_CFI_MAX_VMA_STEPS &&
		       (prev = vma_prev(&vmi)) != NULL) {
			if (vma_is_anonymous(prev) || prev->vm_file != target_file)
				break;
			if (prev->vm_pgoff == 0) {
				*elf_base = prev->vm_start;
				return true;
			}
		}
	}

	return false;
}

/**
 * find_user_eh_frame_hdr() - Resolve PT_GNU_EH_FRAME for a user IP with caching
 * @state: User unwind walk state holding the per-walk VMA cache.
 * @ip: Lookup instruction pointer in current->mm.
 * @out_hdr_uaddr: Output user virtual address of .eh_frame_hdr.
 * @out_hdr_size: Output size in bytes of .eh_frame_hdr.
 *
 * Consults @state->cfi_cache before taking mmap_read_lock_killable(). Negative
 * lookups for executable VMAs lacking ELF headers or PT_GNU_EH_FRAME (such as
 * JIT regions) are also cached with eh_hdr_uaddr == 0 to avoid repeated lock
 * acquisitions during a stack walk.
 *
 * Return: 0 on success, -ENOENT if no PT_GNU_EH_FRAME covers @ip's VMA,
 * -EINTR if killed while waiting for mmap_lock, -EFAULT on user copy fault, or
 * -EINVAL if current->mm is absent or @state->ws is unsupported.
 */
static int find_user_eh_frame_hdr(struct unwind_user_state *state,
				  unsigned long ip,
				  unsigned long *out_hdr_uaddr,
				  size_t *out_hdr_size)
{
	struct mm_struct *mm = current->mm;
	unsigned long vma_start = 0, vma_end = 0, elf_base = 0;
	bool found_base;
	unsigned int i, slot;
	int err;

	if (!mm)
		return -EINVAL;

	/* Check per-walk VMA cache first */
	for (i = 0; i < ARRAY_SIZE(state->cfi_cache); i++) {
		const struct unwind_user_cfi_cache *c = &state->cfi_cache[i];

		if (c->valid && ip >= c->vma_start && ip < c->vma_end) {
			if (!c->eh_hdr_uaddr)
				return -ENOENT;
			*out_hdr_uaddr = c->eh_hdr_uaddr;
			*out_hdr_size = c->eh_hdr_size;
			return 0;
		}
	}

	/*
	 * Resolve the executable VMA and its base ELF mapping (pgoff == 0)
	 * under mmap_read_lock, then drop mmap_read_lock BEFORE any faultable
	 * copy_from_user() calls.
	 */
	if (mmap_read_lock_killable(mm))
		return -EINTR;

	found_base = lookup_vma_elf_base_locked(mm, ip, &vma_start, &vma_end,
						&elf_base);
	mmap_read_unlock(mm);

	if (!vma_end)
		return -ENOENT;

	slot = state->cfi_cache_next++ % ARRAY_SIZE(state->cfi_cache);
	state->cfi_cache[slot].vma_start = vma_start;
	state->cfi_cache[slot].vma_end = vma_end;
	state->cfi_cache[slot].eh_hdr_uaddr = 0;
	state->cfi_cache[slot].eh_hdr_size = 0;
	state->cfi_cache[slot].valid = true;

	if (!found_base)
		return -ENOENT;

	if (state->ws == 8)
		err = parse_user_elf64_eh_hdr(elf_base, out_hdr_uaddr, out_hdr_size);
	else if (state->ws == 4)
		err = parse_user_elf32_eh_hdr(elf_base, out_hdr_uaddr, out_hdr_size);
	else
		return -EINVAL;

	if (err)
		return err;

	state->cfi_cache[slot].eh_hdr_uaddr = *out_hdr_uaddr;
	state->cfi_cache[slot].eh_hdr_size = *out_hdr_size;
	return 0;
}

/**
 * unwind_user_next_cfi() - Compute the Minimal DWARF CFI frame rule for @state
 * @state: Current user-space unwind state (may set @state->done on bottom).
 * @out_frame: Output frame recovery rule for unwind_user_next_common().
 * @out_signal: Set to true if the evaluated FDE represents a signal frame.
 *
 * Looks up the user binary's PT_GNU_EH_FRAME table, evaluates the Minimal
 * DWARF CFI bytecode at @state->ip (or @state->ip - 1 for normal call return
 * addresses), and translates the resulting &struct dwarf_cfi_row into a
 * &struct unwind_user_frame.
 *
 * Return: 0 on success, -ENOENT if no FDE covers @state->ip or if
 * DW_CFA_undefined marks the bottom of the stack (setting @state->done), or a
 * negative errno (-EINVAL, -EFAULT, -EOVERFLOW, -EINTR) on failure.
 */
int unwind_user_next_cfi(struct unwind_user_state *state,
			 struct unwind_user_frame *out_frame, bool *out_signal)
{
	struct dwarf_cfi_arch arch;
	struct dwarf_cfi_row row;
	unsigned long lookup_ip, hdr_uaddr;
	size_t hdr_size;
	int err;

	if (!unwind_user_cfi_arch(state->ws, &arch))
		return -EINVAL;

	lookup_ip = (state->topmost || state->signal) ? state->ip : state->ip - 1;

	err = find_user_eh_frame_hdr(state, lookup_ip, &hdr_uaddr, &hdr_size);
	if (!err)
		err = dwarf_cfi_unwind_user_eh_frame_hdr(hdr_uaddr, hdr_size,
							 lookup_ip, &arch, &row);
	if (err == -ENOENT && lookup_ip != state->ip) {
		/*
		 * A signal trampoline without a leading NOP has state->ip at
		 * the exact start of its FDE, where state->ip - 1 misses.
		 */
		err = find_user_eh_frame_hdr(state, state->ip, &hdr_uaddr,
					     &hdr_size);
		if (!err)
			err = dwarf_cfi_unwind_user_eh_frame_hdr(hdr_uaddr,
								 hdr_size,
								 state->ip,
								 &arch, &row);
		if (!err && !row.signal)
			err = -ENOENT;
	}
	if (err)
		return err;

	/* Explicit DW_CFA_undefined on RA marks bottom of stack (_start/clone) */
	if (row.ra_rule == DWARF_CFI_RULE_UNDEFINED) {
		state->done = true;
		return -ENOENT;
	}

	if (row.cfa_base != DWARF_CFI_BASE_SP &&
	    row.cfa_base != DWARF_CFI_BASE_FP &&
	    row.cfa_base != DWARF_CFI_BASE_FP_INDIRECT &&
	    row.cfa_base != DWARF_CFI_BASE_SP_INDIRECT)
		return -EINVAL;
	if (row.ra_rule == DWARF_CFI_RULE_SAME) {
		if (!state->ra_valid)
			return -EINVAL;
	} else if (row.ra_rule != DWARF_CFI_RULE_OFFSET &&
		   row.ra_rule != DWARF_CFI_RULE_SP_OFFSET) {
		return -EINVAL;
	}

	memset(out_frame, 0, sizeof(*out_frame));
	out_frame->use_fp = (row.cfa_base == DWARF_CFI_BASE_FP ||
			     row.cfa_base == DWARF_CFI_BASE_FP_INDIRECT);
	out_frame->cfa_indirect = (row.cfa_base == DWARF_CFI_BASE_FP_INDIRECT ||
				   row.cfa_base == DWARF_CFI_BASE_SP_INDIRECT);
	out_frame->cfa_off = row.cfa_off;
	out_frame->ra_from_reg = (row.ra_rule == DWARF_CFI_RULE_SAME);
	out_frame->ra_from_sp = (row.ra_rule == DWARF_CFI_RULE_SP_OFFSET);
	out_frame->ra_signed = row.ra_signed;
	out_frame->ra_off = row.ra_off;
	if (row.fp_rule == DWARF_CFI_RULE_OFFSET) {
		out_frame->fp_off = row.fp_off;
	} else if (row.fp_rule == DWARF_CFI_RULE_FP_OFFSET) {
		out_frame->fp_from_fp = true;
		out_frame->fp_off = row.fp_off;
	} else if (row.fp_rule == DWARF_CFI_RULE_SP_OFFSET) {
		out_frame->fp_from_sp = true;
		out_frame->fp_off = row.fp_off;
	}
	*out_signal = row.signal;
	return 0;
}
