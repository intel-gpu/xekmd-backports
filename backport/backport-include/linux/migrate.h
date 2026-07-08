/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_MIGRATE_H
#define __BACKPORT_LINUX_MIGRATE_H

#include_next <linux/migrate.h>
#include <linux/errno.h>

#ifndef MIGRATE_VMA_SELECT_DEVICE_COHERENT
#define MIGRATE_VMA_SELECT_DEVICE_COHERENT 4
#endif

#ifndef MIGRATE_VMA_SELECT_COMPOUND
#define MIGRATE_VMA_SELECT_COMPOUND 8
#endif

#ifdef BPM_MIGRATE_DEVICE_PFNS_NOT_PRESENT

static inline int
backport_migrate_device_pfns(unsigned long *src_pfns, unsigned long npages)
{
	return -EOPNOTSUPP;
}

#define migrate_device_pfns(src_pfns, npages) \
	backport_migrate_device_pfns(src_pfns, npages)

/*
 * Kernels missing migrate_device_pfns() also miss the newer split helpers.
 * Keep these as explicit no-ops because full SVM is gated off on this target.
 */
static inline void
backport_migrate_device_pages(unsigned long *src_pfns,
			      unsigned long *dst_pfns,
			      unsigned long npages)
{
}

static inline void
backport_migrate_device_finalize(unsigned long *src_pfns,
				 unsigned long *dst_pfns,
				 unsigned long npages)
{
}

#define migrate_device_pages(src_pfns, dst_pfns, npages) \
	backport_migrate_device_pages((src_pfns), (dst_pfns), (npages))

#define migrate_device_finalize(src_pfns, dst_pfns, npages) \
	backport_migrate_device_finalize((src_pfns), (dst_pfns), (npages))
#endif
#endif /* __BACKPORT_LINUX_MIGRATE_H */
