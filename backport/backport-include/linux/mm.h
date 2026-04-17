/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BACKPORT_MM_H
#define _BACKPORT_MM_H

#include_next<linux/mm.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 11, 0)

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

static inline int follow_pfnmap_start(struct follow_pfnmap_args *args)
{
    /*
     * follow_pfn() internally does:
     *   pte_offset_map_lock() → read pfn → pte_unmap_unlock()
     * i.e. it maps, reads, AND unmaps the PTE atomically.
     */
    return follow_pfn(args->vma, args->address, &args->pfn);
}

static inline void follow_pfnmap_end(struct follow_pfnmap_args *args)
{
    /*
     * No-op on kernels < 6.11:
     * follow_pfn() already called pte_unmap_unlock() internally.
     * There is NO dangling PTE mapping to clean up here.
     */
}

#endif

#ifdef BPM_PIN_USER_PAGES_REMOTE_ARG6_NOT_PRESENT
long bkpt_pin_user_pages_remote(struct mm_struct *mm,
			   unsigned long start, unsigned long nr_pages,
			   unsigned int gup_flags, struct page **pages,
			   int *locked);
#define pin_user_pages_remote bkpt_pin_user_pages_remote
#endif

#endif
