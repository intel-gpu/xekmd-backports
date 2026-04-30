/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2007-2008 Advanced Micro Devices, Inc.
 * Author: Joerg Roedel <joerg.roedel@amd.com>
 */

#ifndef __BACKPORT_IOMMU_H
#define __BACKPORT_IOMMU_H

#include_next <linux/iommu.h>

#ifdef HAVE_LINUX_DMA_IOMMU_H
#include <linux/dma-iommu.h>
#endif

#define IRQ_DOMAIN_FLAG_ISOLATED_MSI 32
#ifndef arch_is_isolated_msi
#define arch_is_isolated_msi() false
#endif

#ifndef IOMMU_CAP_ENFORCE_CACHE_COHERENCY
#define IOMMU_CAP_ENFORCE_CACHE_COHERENCY IOMMU_CAP_CACHE_COHERENCY
#endif

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
void iommu_group_release_dma_owner(struct iommu_group *group);
bool iommu_group_dma_owner_claimed(struct iommu_group *group);
struct iommu_domain *iommu_paging_domain_alloc_flags(struct device *dev,
						     unsigned int flags);
static inline struct iommu_domain *iommu_paging_domain_alloc(struct device *dev)
{
	return iommu_paging_domain_alloc_flags(dev, 0);
}
extern bool iommu_group_has_isolated_msi(struct iommu_group *group);
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
static inline struct iommu_domain *iommu_paging_domain_alloc(struct device *dev)
{
	return ERR_PTR(-ENODEV);
}
static inline struct iommu_domain *iommu_paging_domain_alloc_flags(struct device *dev,
						     unsigned int flags)
{
	return ERR_PTR(-ENODEV);
}
#endif /*CONFIG_IOMMU_API */
#endif
#endif
