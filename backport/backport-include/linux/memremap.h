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
#define zone_device_page_init(...) do { } while (0)
#endif

#ifdef BPM_FOLIO_ZONE_DEVICE_DATA_NOT_PRESENT
/*
 * folio_zone_device_data - return zone_device_data for a device-private folio
 * @folio: the folio
 *
 * Added in v6.7. For older kernels, access zone_device_data via
 * folio->page.zone_device_data directly.
 */
static inline void *folio_zone_device_data(const struct folio *folio)
{
	return folio->page.zone_device_data;
}
#endif /* BPM_FOLIO_ZONE_DEVICE_DATA_NOT_PRESENT */

#endif /* __BACKPORT_LINUX_MEMREMAP_H */
