// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2007-2008 Advanced Micro Devices, Inc.
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#include <linux/iommu.h>

#ifdef BPM_IOMMU_PAGING_DOMAIN_ALLOC_NOT_PRESENT

/*
 * Internal equivalent of device_iommu_mapped() for when we care that a device
 * actually has API ops, and don't want false positives from VFIO-only groups.
 */
static bool dev_has_iommu(struct device *dev)
{
	return dev->iommu && dev->iommu->iommu_dev;
}

/**
 * iommu_paging_domain_alloc() - Allocate a paging domain
 * @dev: device for which the domain is allocated
 *
 * Allocate a paging domain which will be managed by a kernel driver. Return
 * allocated domain if successful, or a ERR pointer for failure.
 */
struct iommu_domain *iommu_paging_domain_alloc(struct device *dev)
{
	if (!dev_has_iommu(dev))
		return ERR_PTR(-ENODEV);

	return iommu_domain_alloc(dev->bus);
}
EXPORT_SYMBOL_GPL(iommu_paging_domain_alloc);
#endif
