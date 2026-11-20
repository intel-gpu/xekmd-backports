/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BACKPORT_MM_INLINE_H
#define BACKPORT_MM_INLINE_H

#include <linux/mm_types.h>
#include_next <linux/mm_inline.h>

#ifdef BPM_NUM_PAGES_CONTIGUOUS_NOT_PRESENT
/**
 * num_pages_contiguous() - determine the number of contiguous pages
 *			    that represent contiguous PFNs
 * @pages: an array of page pointers
 * @nr_pages: length of the array, at least 1
 *
 * Determine the number of contiguous pages that represent contiguous PFNs
 * in @pages, starting from the first page.
 *
 * In some kernel configs contiguous PFNs will not have contiguous struct
 * pages. In these configurations num_pages_contiguous() will return a num
 * smaller than ideal number. The caller should continue to check for pfn
 * contiguity after each call to num_pages_contiguous().
 *
 * Returns the number of contiguous pages.
 */
static inline size_t num_pages_contiguous(struct page **pages, size_t nr_pages)
{
	struct page *cur_page = pages[0];
	unsigned long section = memdesc_section((memdesc_flags_t){ .f = cur_page->flags });
	size_t i;

	for (i = 1; i < nr_pages; i++) {
		if (++cur_page != pages[i])
			break;
		/*
		 * In unproblematic kernel configs, page_to_section() == 0 and
		 * the whole check will get optimized out.
		 */
		if (memdesc_section((memdesc_flags_t){ .f = cur_page->flags }) != section)
			break;
	}

	return i;
}
#endif /* BPM_NUM_PAGES_CONTIGUOUS_NOT_PRESENT */

#endif
