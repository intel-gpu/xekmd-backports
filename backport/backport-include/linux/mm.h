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

#ifndef VM_ALLOW_ANY_UNCACHED
/*
 * This flag is used to connect VFIO to arch specific KVM code. It
 * indicates that the memory under this VMA is safe for use with any
 * non-cachable memory type inside KVM. Some VFIO devices, on some
 * platforms, are thought to be unsafe and can cause machine crashes
 * if KVM does not lock down the memory type.
 */
#ifdef CONFIG_64BIT
#define VM_ALLOW_ANY_UNCACHED_BIT	39
#define VM_ALLOW_ANY_UNCACHED		BIT(VM_ALLOW_ANY_UNCACHED_BIT)
#else
#define VM_ALLOW_ANY_UNCACHED		VM_NONE
#endif
#endif

#endif
