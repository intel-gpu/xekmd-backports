/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2007-2008 Advanced Micro Devices, Inc.
 * Author: Joerg Roedel <joerg.roedel@amd.com>
 */

#ifndef __BACKPORT_IOMMU_H
#define __BACKPORT_IOMMU_H

#include_next <linux/iommu.h>

#ifdef BPM_IOMMU_PAGING_DOMAIN_ALLOC_NOT_PRESENT

#ifdef CONFIG_IOMMU_API
struct iommu_domain *iommu_paging_domain_alloc(struct device *dev);
#else
static inline struct iommu_domain *iommu_paging_domain_alloc(struct device *dev)
{
	return ERR_PTR(-ENODEV);
}
#endif
#endif
#endif
