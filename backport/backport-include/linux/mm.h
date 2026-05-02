/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_MM_H
#define __BACKPORT_LINUX_MM_H

#include_next <linux/mm.h>

#ifdef BPM_VM_FLAGS_SET_NOT_PRESENT
#define vm_flags_set(vma, flags)	((vma)->vm_flags |= (flags))

#define vm_flags_clear(vma, flags)	((vma)->vm_flags &= ~(flags))

#define vm_flags_mod(vma, set, clear)	\
	do {				\
		vm_flags_set((vma), (set));	\
		vm_flags_clear((vma), (clear));	\
	} while (0)
#endif

#ifdef BPM_FOLIO_PUT_NOT_PRESENT
#define folio_file_page(folio, idx) ((struct page *)(folio))
#define folio_put(folio) put_page((struct page *)(folio))
#define folio_mark_accessed(folio) mark_page_accessed((struct page *)(folio))
#define folio_lock(folio) lock_page((struct page *)(folio))
#define folio_unlock(folio) unlock_page((struct page *)(folio))
#define folio_mark_dirty(folio) set_page_dirty((struct page *)(folio))
#define folio_mapped(folio) page_mapped((struct page *)(folio))
#define folio_clear_dirty_for_io(folio) clear_page_dirty_for_io((struct page *)(folio))
#define folio_set_reclaim(folio) SetPageReclaim((struct page *)(folio))
#define folio_clear_reclaim(folio) ClearPageReclaim((struct page *)(folio))
#define folio_test_writeback(folio) PageWriteback((struct page *)(folio))
#endif

#ifdef BPM_PIN_USER_PAGES_REMOTE_ARG6_NOT_PRESENT
static inline long bkpt_pin_user_pages_remote(struct mm_struct *mm,
			   unsigned long start, unsigned long nr_pages,
			   unsigned int gup_flags, struct page **pages,
			   int *locked)
{
	return pin_user_pages_remote(mm, start, nr_pages, gup_flags, pages, NULL, locked);
}
#define pin_user_pages_remote bkpt_pin_user_pages_remote
#endif

#ifdef BPM_FOLLOW_PFNMAP_START_NOT_PRESENT
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
     * No-op on kernels < 6.12:
     * follow_pfn() already called pte_unmap_unlock() internally.
     * There is NO dangling PTE mapping to clean up here.
     */
}
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

#endif /* __BACKPORT_LINUX_MM_H */
