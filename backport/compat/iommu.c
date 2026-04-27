// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2007-2008 Advanced Micro Devices, Inc.
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#include<linux/iommu.h>
#include<linux/irqdomain.h>

#ifdef BPM_DEVICE_IOMMU_CAPABLE_NOT_PRESENT
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
 * msi_device_has_isolated_msi - True if the device has isolated MSI
 * @dev: The device to check
 *
 * Isolated MSI means that HW modeled by an irq_domain on the path from the
 * initiating device to the CPU will validate that the MSI message specifies an
 * interrupt number that the device is authorized to trigger. This must block
 * devices from triggering interrupts they are not authorized to trigger.
 * Currently authorization means the MSI vector is one assigned to the device.
 *
 * This is interesting for securing VFIO use cases where a rouge MSI (eg created
 * by abusing a normal PCI MemWr DMA) must not allow the VFIO userspace to
 * impact outside its security domain, eg userspace triggering interrupts on
 * kernel drivers, a VM triggering interrupts on the hypervisor, or a VM
 * triggering interrupts on another VM.
 */
bool msi_device_has_isolated_msi(struct device *dev)
{
        struct irq_domain *domain = dev_get_msi_domain(dev);

        for (; domain; domain = domain->parent)
                if (domain->flags & IRQ_DOMAIN_FLAG_ISOLATED_MSI)
                        return true;
        return arch_is_isolated_msi();
}

/**
 * iommu_group_has_isolated_msi() - Compute msi_device_has_isolated_msi()
 *       for a group
 * @group: Group to query
 *
 * IOMMU groups should not have differing values of
 * msi_device_has_isolated_msi() for devices in a group. However nothing
 * directly prevents this, so ensure mistakes don't result in isolation failures
 * by checking that all the devices are the same.
 */
bool iommu_group_has_isolated_msi(struct iommu_group *group)
{
        struct group_device *group_dev;
        bool ret = true;

        mutex_lock(&group->mutex);
        for_each_group_device(group, group_dev)
                ret &= msi_device_has_isolated_msi(group_dev->dev);
        mutex_unlock(&group->mutex);
        return ret;
}
EXPORT_SYMBOL_GPL(iommu_group_has_isolated_msi);

#endif /* BPM_IOMMU_GROUP_HAS_ISOLATED_MSI_NOT_PRESENT */
