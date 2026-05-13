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

#ifdef BPM_FOLIO_FILE_PAGE_NOT_PRESENT
#define folio_file_page(folio, idx) ((struct page *)(folio))
#endif

#ifdef BPM_FOLIO_PUT_NOT_PRESENT
#define folio_put(folio) put_page((struct page *)(folio))
#endif

#ifdef BPM_FOLIO_MARK_ACCESSED_NOT_PRESENT
#define folio_mark_accessed(folio) mark_page_accessed((struct page *)(folio))
#endif

#ifdef BPM_FOLIO_LOCK_NOT_PRESENT
#define folio_lock(folio) lock_page((struct page *)(folio))
#endif

#ifdef BPM_FOLIO_UNLOCK_NOT_PRESENT
#define folio_unlock(folio) unlock_page((struct page *)(folio))
#endif

#ifdef BPM_FOLIO_MARK_DIRTY_NOT_PRESENT
#define folio_mark_dirty(folio) set_page_dirty((struct page *)(folio))
#endif

#ifdef BPM_FOLIO_MAPPED_NOT_PRESENT
#define folio_mapped(folio) page_mapped((struct page *)(folio))
#endif

#ifdef BPM_FOLIO_CLEAR_DIRTY_FOR_IO_NOT_PRESENT
#define folio_clear_dirty_for_io(folio) clear_page_dirty_for_io((struct page *)(folio))
#endif

#ifdef BPM_FOLIO_SET_RECLAIM_NOT_PRESENT
#define folio_set_reclaim(folio) SetPageReclaim((struct page *)(folio))
#endif

#ifdef BPM_FOLIO_CLEAR_RECLAIM_NOT_PRESENT
#define folio_clear_reclaim(folio) ClearPageReclaim((struct page *)(folio))
#endif

#ifdef BPM_FOLIO_TEST_WRITEBACK_NOT_PRESENT
#define folio_test_writeback(folio) PageWriteback((struct page *)(folio))
#endif

#endif /* __BACKPORT_LINUX_MM_H */
