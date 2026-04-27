/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2007-2008 Advanced Micro Devices, Inc.
 * Author: Joerg Roedel <joerg.roedel@amd.com>
 */

#ifndef __BACKPORT_IOMMU_H
#define __BACKPORT_IOMMU_H

#include_next <linux/iommu.h>

#ifdef BPM_DEVICE_IOMMU_CAPABLE_NOT_PRESENT
#ifdef CONFIG_IOMMU_API
extern bool device_iommu_capable(struct device *dev, enum iommu_cap cap);
#else
static inline bool device_iommu_capable(struct device *dev, enum iommu_cap cap)
{
	return false;
}
#endif /* CONFIG_IOMMU_API */
#endif /* BPM_DEVICE_IOMMU_CAPABLE_NOT_PRESENT */

#ifndef IOMMU_CAP_ENFORCE_CACHE_COHERENCY
#define IOMMU_CAP_ENFORCE_CACHE_COHERENCY IOMMU_CAP_CACHE_COHERENCY
#endif

#ifdef BPM_IOMMU_GROUP_CLAIM_DMA_OWNER_NOT_PRESENT
#ifdef CONFIG_IOMMU_API
int iommu_group_claim_dma_owner(struct iommu_group *group, void *owner);
void iommu_group_release_dma_owner(struct iommu_group *group);
bool iommu_group_dma_owner_claimed(struct iommu_group *group);
#else
static inline int
iommu_group_claim_dma_owner(struct iommu_group *group, void *owner)
{
	return -ENODEV;
}

static inline void iommu_group_release_dma_owner(struct iommu_group *group)
{
}

static inline bool iommu_group_dma_owner_claimed(struct iommu_group *group)
{
	return false;
}
#endif /*CONFIG_IOMMU_API */
#endif /* BPM_IOMMU_GROUP_CLAIM_DMA_OWNER_NOT_PRESENT */

#ifdef BPM_IOMMU_PAGING_DOMAIN_ALLOC_NOT_PRESENT
#ifdef CONFIG_IOMMU_API
struct iommu_domain *iommu_paging_domain_alloc(struct device *dev);
#else
static inline struct iommu_domain *iommu_paging_domain_alloc(struct device *dev)
{
	return ERR_PTR(-ENODEV);
}
#endif /*CONFIG_IOMMU_API */
#endif /* BPM_IOMMU_PAGING_DOMAIN_ALLOC_NOT_PRESENT */

#ifdef BPM_IOMMU_MAP_GFP_NOT_PRESENT
static inline int bpm_iommu_map(struct iommu_domain *domain, unsigned long iova,
		     phys_addr_t paddr, size_t size, int prot, gfp_t gfp)
{
	return iommu_map(domain, iova, paddr, size, prot);
}
#define iommu_map bpm_iommu_map
#endif

#endif /* __BACKPORT_IOMMU_H */
