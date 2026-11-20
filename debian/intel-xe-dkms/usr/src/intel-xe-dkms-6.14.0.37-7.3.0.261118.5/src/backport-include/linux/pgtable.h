/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_PGTABLE_H
#define __BACKPORT_LINUX_PGTABLE_H

#include_next <linux/pgtable.h>

#ifndef PMD_ORDER
#define PMD_ORDER	(PMD_SHIFT - PAGE_SHIFT)
#endif

#ifndef PUD_ORDER
#define PUD_ORDER	(PUD_SHIFT - PAGE_SHIFT)
#endif

#endif /* __BACKPORT_LINUX_PGTABLE_H */
