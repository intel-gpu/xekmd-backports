/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2007-2008 Advanced Micro Devices, Inc.
 * Author: Joerg Roedel <joerg.roedel@amd.com>
 */

#ifndef __BACKPORT_IOMMU_H
#define __BACKPORT_IOMMU_H

#include_next <linux/iommu.h>

//#ifdef TRUE

#ifdef CONFIG_IOMMU_API
extern bool device_iommu_capable(struct device *dev, enum iommu_cap cap);
#else
static inline bool device_iommu_capable(struct device *dev, enum iommu_cap cap)
{
	return false;
}
#endif
//#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)
static inline int bpm_iommu_map(struct iommu_domain *domain, unsigned long iova,
		     phys_addr_t paddr, size_t size, int prot, gfp_t gfp)
{
	return iommu_map(domain, iova, paddr, size, prot);
}
#define iommu_map bpm_iommu_map
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
#ifdef CONFIG_IOMMU_API
int iommu_group_claim_dma_owner(struct iommu_group *group, void *owner);
#else
static inline int
iommu_group_claim_dma_owner(struct iommu_group *group, void *owner)
{
	return -ENODEV;
}
#endif /*CONFIG_IOMMU_API */
#endif
#endif
