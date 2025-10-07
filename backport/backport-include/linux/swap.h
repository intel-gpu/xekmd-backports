/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_SWAP_H
#define __BACKPORT_LINUX_SWAP_H

#include_next <linux/swap.h>

#ifdef CONFIG_HIGHMEM
static inline void *kmap_local_page_try_from_panic(struct page *page)
{
        if (!PageHighMem(page))
                return page_address(page);
        /* If the page is in HighMem, it's not safe to kmap it.*/
        return NULL;
}
#else
static inline void *kmap_local_page_try_from_panic(struct page *page)
{
        return page_address(page);
}
#endif

#endif /* __BACKPORT_LINUX_SWAP_H */
