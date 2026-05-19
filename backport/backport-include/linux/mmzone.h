/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_MMZONE_H
#define __BACKPORT_LINUX_MMZONE_H
#include_next <linux/mmzone.h>

#ifndef MAX_PAGE_ORDER
#define MAX_PAGE_ORDER MAX_ORDER
#endif

#ifdef BPM_PAGE_PGMAP_NOT_PRESENT
struct dev_pagemap;
/*
 * v7.0 moved pgmap lookup into page_pgmap(). On 6.6 the field
 * lives directly in struct page (ZONE_DEVICE pages).
 */
static inline struct dev_pagemap *page_pgmap(const struct page *page)
{
	return page->pgmap;
}
#endif /* BPM_PAGE_PGMAP_NOT_PRESENT */

#endif /* __BACKPORT_LINUX_MMZONE_H */
