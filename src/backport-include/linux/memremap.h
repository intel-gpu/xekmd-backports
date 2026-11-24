/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __BACKPORT_LINUX_MEMREMAP_H
#define __BACKPORT_LINUX_MEMREMAP_H

#include_next <linux/memremap.h>

#ifdef BPM_FOLIO_ZONE_DEVICE_DATA_NOT_PRESENT
struct folio;
static inline void *folio_zone_device_data(const struct folio *folio)
{
#ifdef BPM_FOLIO_PUT_NOT_PRESENT
	return ((const struct page *)folio)->zone_device_data;
#else
	VM_WARN_ON_FOLIO(!folio_is_device_private(folio), folio);
	return folio->page.zone_device_data;
#endif
}
#endif /* BPM_FOLIO_ZONE_DEVICE_DATA_NOT_PRESENT */

#ifdef BPM_FOLIO_SET_ZONE_DEVICE_DATA_NOT_PRESENT
static inline void folio_set_zone_device_data(struct folio *folio, void *data)
{
#ifdef BPM_FOLIO_PUT_NOT_PRESENT
	((struct page *)folio)->zone_device_data = data;
#else
	VM_WARN_ON_FOLIO(!folio_is_device_private(folio), folio);
	folio->page.zone_device_data = data;
#endif
}
#endif

#ifdef BPM_ZONE_DEVICE_PAGE_INIT_3ARGS_NOT_PRESENT
/* Has 2-arg signature: (page, order) */
#define zone_device_page_init(page, pgmap, order) \
	zone_device_page_init(page, order)
#elif defined(BPM_ZONE_DEVICE_PAGE_INIT_2ARGS_NOT_PRESENT)
/* Has 1-arg signature */
#define zone_device_page_init(page, pgmap, order) \
	zone_device_page_init(page)
#elif defined(BPM_ZONE_DEVICE_PAGE_INIT_1ARG_NOT_PRESENT)
#undef zone_device_page_init
#define zone_device_page_init(page, pgmap, order) \
        do { } while (0)
#endif

#ifdef BPM_ZONE_DEVICE_FOLIO_INIT_3ARGS_NOT_PRESENT
#include <linux/mmdebug.h>
#include <linux/page_ref.h>
/*
 * Reinitialize per-page metadata left by a previously allocated folio of a
 * different order before calling the 2-arg helper.
 */
static inline void backport_zone_device_folio_init(struct folio *folio,
						   struct dev_pagemap *pgmap,
						   unsigned int order)
{
	struct page *page = &folio->page;
	unsigned long i;

	for (i = 0; i < (1UL << order); i++, page++) {
		/* Clear possible order (as old page[1]), PG_head and PG_locked */
		page->flags &= ~0xffUL;
		page->mapping = NULL;
		/* Also clears a stale compound_head */
		page->pgmap = pgmap;
		page->share = 0;
		VM_WARN_ON_ONCE_PAGE(page_ref_count(page), page);
	}

	zone_device_folio_init(folio, order);
}

#define zone_device_folio_init(folio, pgmap, order) \
	backport_zone_device_folio_init(folio, pgmap, order)
#endif

#endif /* __BACKPORT_LINUX_MEMREMAP_H */
