/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_MMZONE_H
#define __BACKPORT_LINUX_MMZONE_H
#include_next <linux/mmzone.h>

#ifndef MAX_PAGE_ORDER
#define MAX_PAGE_ORDER MAX_ORDER
#endif

#endif /* __BACKPORT_LINUX_MMZONE_H */
