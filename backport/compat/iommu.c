// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2007-2008 Advanced Micro Devices, Inc.
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#include<linux/iommu.h>

//#ifdef TRUE
#ifdef CONFIG_IOMMU_API 
/*
 * Internal equivalent of device_iommu_mapped() for when we care that a device
 * actually has API ops, and don't want false positives from VFIO-only groups.
 */
static bool dev_has_iommu(struct device *dev)
{
	return dev->iommu && dev->iommu->iommu_dev;
}
static inline const struct iommu_ops *dev_iommu_ops(struct device *dev)
{
	/*
	 * Assume that valid ops must be installed if iommu_probe_device()
	 * has succeeded. The device ops are essentially for internal use
	 * within the IOMMU subsystem itself, so we should be able to trust
	 * ourselves not to misuse the helper.
	 */
	return dev->iommu->iommu_dev->ops;
}
/**
 * device_iommu_capable() - check for a general IOMMU capability
 * @dev: device to which the capability would be relevant, if available
 * @cap: IOMMU capability
 *
 * Return: true if an IOMMU is present and supports the given capability
 * for the given device, otherwise false.
 */
bool device_iommu_capable(struct device *dev, enum iommu_cap cap)
{
	const struct iommu_ops *ops;

	if (!dev_has_iommu(dev))
		return false;

	ops = dev_iommu_ops(dev);
	if (!ops->capable)
		return false;

	return ops->capable(cap);
}
EXPORT_SYMBOL_GPL(device_iommu_capable);
#endif

//#endif
