/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_SWAP_H
#define __BACKPORT_LINUX_SWAP_H

#include_next <linux/swap.h>

#ifndef KMAP_SAFE_PAGE_ADDRESS
#ifdef CONFIG_HIGHMEM
#define KMAP_SAFE_PAGE_ADDRESS(page) \
        (PageHighMem(page) ? NULL : page_address(page))
#else
#define KMAP_SAFE_PAGE_ADDRESS(page) \
        page_address(page)
#endif
#endif

#ifdef BPM_KMAP_LOCAL_PAGE_TRY_FROM_PANIC_NOT_PRESENT
static inline void *kmap_local_page_try_from_panic(struct page *page)
{
        return KMAP_SAFE_PAGE_ADDRESS(page);
}
#endif

#ifdef BPM_KMAP_LOCAL_PAGE_TRY_FROM_PANIC_NONCONST_PRESENT
static inline void *backport_kmap_const(const struct page *page)
{
        return KMAP_SAFE_PAGE_ADDRESS(page);
}
#endif

#endif /* __BACKPORT_LINUX_SWAP_H */
