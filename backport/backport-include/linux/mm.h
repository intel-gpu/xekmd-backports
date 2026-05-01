/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BACKPORT_MM_H
#define _BACKPORT_MM_H

#include_next<linux/mm.h>

#ifdef BPM_FOLLOW_PFNMAP_NOT_PRESENT
struct follow_pfnmap_args {
	/**
	 * Inputs:
	 * @vma: Pointer to @vm_area_struct struct
	 * @address: the virtual address to walk
	 */
	struct vm_area_struct *vma;
	unsigned long address;
	/**
	 * Internals:
	 *
	 * The caller shouldn't touch any of these.
	 */
	spinlock_t *lock;
	pte_t *ptep;
	/**
	 * Outputs:
	 *
	 * @pfn: the PFN of the address
	 * @addr_mask: address mask covering pfn
	 * @pgprot: the pgprot_t of the mapping
	 * @writable: whether the mapping is writable
	 * @special: whether the mapping is a special mapping (real PFN maps)
	 */
	unsigned long pfn;
	unsigned long addr_mask;
	pgprot_t pgprot;
	bool writable;
	bool special;
};

int follow_pfnmap_start(struct follow_pfnmap_args *args);
void follow_pfnmap_end(struct follow_pfnmap_args *args);
#endif
#endif
