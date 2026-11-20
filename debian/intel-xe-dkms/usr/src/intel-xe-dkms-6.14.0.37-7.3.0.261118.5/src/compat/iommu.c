// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2007-2008 Advanced Micro Devices, Inc.
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#include<linux/iommu.h>
#include<linux/irqdomain.h>

#if defined (BPM_DEVICE_IOMMU_CAPABLE_NOT_PRESENT) || defined (BPM_IOMMU_PAGING_DOMAIN_ALLOC_NOT_PRESENT)
/*
 * Internal equivalent of device_iommu_mapped() for when we care that a device
 * actually has API ops, and don't want false positives from VFIO-only groups.
 */
static bool dev_has_iommu(struct device *dev)
{
	return dev->iommu && dev->iommu->iommu_dev;
}
#endif

#ifdef BPM_DEVICE_IOMMU_CAPABLE_NOT_PRESENT
#ifdef CONFIG_IOMMU_API
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
#endif /* CONFIG_IOMMU_API */
#endif /* BPM_DEVICE_IOMMU_CAPABLE_NOT_PRESENT */

struct iommu_group {
        struct kobject kobj;
        struct kobject *devices_kobj;
        struct list_head devices;
        struct mutex mutex;
        void *iommu_data;
        void (*iommu_data_release)(void *iommu_data);
        char *name;
        int id;
        struct iommu_domain *default_domain;
        struct iommu_domain *blocking_domain;
        struct iommu_domain *domain;
        struct list_head entry;
        unsigned int owner_cnt;
        void *owner;
};

struct group_device {
        struct list_head list;
        struct device *dev;
        char *name;
};


#ifdef BPM_IOMMU_GROUP_CLAIM_DMA_OWNER_NOT_PRESENT

int iommu_group_claim_dma_owner(struct iommu_group *group, void *owner)
{
        return 0;
}
EXPORT_SYMBOL_GPL(iommu_group_claim_dma_owner);

void iommu_group_release_dma_owner(struct iommu_group *group)
{
}
EXPORT_SYMBOL_GPL(iommu_group_release_dma_owner);

bool iommu_group_dma_owner_claimed(struct iommu_group *group)
{
	return false;
}
EXPORT_SYMBOL_GPL(iommu_group_dma_owner_claimed);
#endif /* BPM_IOMMU_GROUP_CLAIM_DMA_OWNER_NOT_PRESENT */

#ifdef BPM_IOMMU_PAGING_DOMAIN_ALLOC_NOT_PRESENT
/*
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
#endif /* BPM_IOMMU_PAGING_DOMAIN_ALLOC_NOT_PRESENT */

#ifdef BPM_IOMMU_GROUP_HAS_ISOLATED_MSI_NOT_PRESENT
/* Iterate over each struct group_device in a struct iommu_group */
#define for_each_group_device(group, pos) \
        list_for_each_entry(pos, &(group)->devices, list)

/**
 * iommu_group_has_isolated_msi() - Compute whether the group's MSIs are isolated
 * @group: Group to query
 *
 * This shim is only built on kernels prior to v6.5, which lack the per-device
 * ISOLATED_MSI irq_domain flag used by the upstream helper. Reproduce what those
 * kernels' own VFIO code did to detect interrupt remapping: it is considered
 * present if either the global irq_domain_check_msi_remap() reports a remapping
 * MSI domain, or the IOMMU advertises IOMMU_CAP_INTR_REMAP for the group's
 * devices (e.g. Intel VT-d / AMD-Vi with interrupt remapping enabled). Relying
 * on irq_domain_check_msi_remap() alone misses platforms that only expose IR
 * through the IOMMU capability, wrongly forcing the "unsafe interrupts" path.
 */
bool iommu_group_has_isolated_msi(struct iommu_group *group)
{
        struct group_device *group_dev;
        bool ret = false;

        if (irq_domain_check_msi_remap() || arch_is_isolated_msi())
                return true;

        mutex_lock(&group->mutex);
        for_each_group_device(group, group_dev) {
                if (device_iommu_capable(group_dev->dev,
                                         IOMMU_CAP_INTR_REMAP)) {
                        ret = true;
                        break;
                }
        }
        mutex_unlock(&group->mutex);
        return ret;
}
EXPORT_SYMBOL_GPL(iommu_group_has_isolated_msi);

#endif /* BPM_IOMMU_GROUP_HAS_ISOLATED_MSI_NOT_PRESENT */
