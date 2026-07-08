/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_MEMREMAP_H
#define __BACKPORT_LINUX_MEMREMAP_H

#include_next <linux/memremap.h>

#ifdef BPM_ZONE_DEVICE_PAGE_INIT_3ARGS_NOT_PRESENT
/*
 * On legacy targets we bypass device-memory migration helpers.
 * Accept any call form and intentionally no-op this initialization.
 */
#undef zone_device_page_init
#define zone_device_page_init(page) do { } while (0)
#endif

#endif /* __BACKPORT_LINUX_MEMREMAP_H */
