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
#endif
