/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_PGTABLE_H
#define __BACKPORT_LINUX_PGTABLE_H

#include_next <linux/pgtable.h>

#ifdef BPM_PMD_ORDER_NOT_PRESENT

#ifdef CONFIG_ARCH_SUPPORTS_PMD_PFNMAP
#define PMD_ORDER	(PMD_SHIFT - PAGE_SHIFT)
#endif

#ifdef CONFIG_ARCH_SUPPORTS_PUD_PFNMAP
#define PUD_ORDER	(PUD_SHIFT - PAGE_SHIFT)
#endif

#endif

#endif /* __BACKPORT_LINUX_PGTABLE_H */
