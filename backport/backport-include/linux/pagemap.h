/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_PAGEMAP_H
#define __BACKPORT_LINUX_PAGEMAP_H

#include_next <linux/pagemap.h>

#ifdef BPM_LINEAR_PAGE_DELTA_NOT_PRESENT
static inline pgoff_t linear_page_delta(const struct vm_area_struct *vma,
				       unsigned long address)
{
	return (address - vma->vm_start) >> PAGE_SHIFT;
}
#endif

#endif /* __BACKPORT_LINUX_PAGEMAP_H */
