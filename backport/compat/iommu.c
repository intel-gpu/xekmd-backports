// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2007-2008 Advanced Micro Devices, Inc.
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#include<linux/iommu.h>

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


#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)

static bool iommu_is_attach_deferred(struct iommu_domain *domain,
				     struct device *dev)
{
	const struct iommu_ops *ops = dev_iommu_ops(dev);

	if (ops->is_attach_deferred)
		return ops->is_attach_deferred(domain, dev);

	return false;
}

static void __iommu_detach_device(struct iommu_domain *domain,
				  struct device *dev)
{
	if (iommu_is_attach_deferred(domain, dev))
		return;

	domain->ops->detach_dev(domain, dev);
//	trace_detach_device_from_domain(dev);
}

static int iommu_group_do_detach_device(struct device *dev, void *data)
{
	struct iommu_domain *domain = data;

	__iommu_detach_device(domain, dev);

	return 0;
}

static int __iommu_group_for_each_dev(struct iommu_group *group, void *data,
				      int (*fn)(struct device *, void *))
{
	struct group_device *device;
	int ret = 0;

	list_for_each_entry(device, &group->devices, list) {
		ret = fn(device->dev, data);
		if (ret)
			break;
	}
	return ret;
}

static int __iommu_attach_device(struct iommu_domain *domain,
				 struct device *dev)
{
	int ret;

	if (unlikely(domain->ops->attach_dev == NULL))
		return -ENODEV;

	ret = domain->ops->attach_dev(domain, dev);
//	if (!ret)
//		trace_attach_device_to_domain(dev);
	return ret;
}

/*
 * IOMMU groups are really the natural working unit of the IOMMU, but
 * the IOMMU API works on domains and devices.  Bridge that gap by
 * iterating over the devices in a group.  Ideally we'd have a single
 * device which represents the requestor ID of the group, but we also
 * allow IOMMU drivers to create policy defined minimum sets, where
 * the physical hardware may be able to distiguish members, but we
 * wish to group them at a higher level (ex. untrusted multi-function
 * PCI devices).  Thus we attach each device.
 */
static int iommu_group_do_attach_device(struct device *dev, void *data)
{
	struct iommu_domain *domain = data;

	return __iommu_attach_device(domain, dev);
}

static int __iommu_group_set_domain(struct iommu_group *group,
				    struct iommu_domain *new_domain)
{
	int ret;

	if (group->domain == new_domain)
		return 0;

	/*
	 * New drivers should support default domains and so the detach_dev() op
	 * will never be called. Otherwise the NULL domain represents some
	 * platform specific behavior.
	 */
	if (!new_domain) {
		if (WARN_ON(!group->domain->ops->detach_dev))
			return -EINVAL;
		__iommu_group_for_each_dev(group, group->domain,
					   iommu_group_do_detach_device);
		group->domain = NULL;
		return 0;
	}

	/*
	 * Changing the domain is done by calling attach_dev() on the new
	 * domain. This switch does not have to be atomic and DMA can be
	 * discarded during the transition. DMA must only be able to access
	 * either new_domain or group->domain, never something else.
	 *
	 * Note that this is called in error unwind paths, attaching to a
	 * domain that has already been attached cannot fail.
	 */
	ret = __iommu_group_for_each_dev(group, new_domain,
					 iommu_group_do_attach_device);
	if (ret)
		return ret;
	group->domain = new_domain;
	return 0;
}

/**
 * iommu_group_claim_dma_owner() - Set DMA ownership of a group
 * @group: The group.
 * @owner: Caller specified pointer. Used for exclusive ownership.
 *
 * This is to support backward compatibility for vfio which manages
 * the dma ownership in iommu_group level. New invocations on this
 * interface should be prohibited.
 */
int iommu_group_claim_dma_owner(struct iommu_group *group, void *owner)
{
	int ret = 0;

	mutex_lock(&group->mutex);
	if (group->owner_cnt) {
		ret = -EPERM;
		goto unlock_out;
	} else {
		if (group->domain && group->domain != group->default_domain) {
			ret = -EBUSY;
			goto unlock_out;
		}

//		ret = __iommu_group_alloc_blocking_domain(group);
		if (ret)
			goto unlock_out;

		ret = __iommu_group_set_domain(group, group->blocking_domain);
		if (ret)
			goto unlock_out;
		group->owner = owner;
	}

	group->owner_cnt++;
unlock_out:
	mutex_unlock(&group->mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(iommu_group_claim_dma_owner);

/**
 * iommu_group_release_dma_owner() - Release DMA ownership of a group
 * @group: The group.
 *
 * Release the DMA ownership claimed by iommu_group_claim_dma_owner().
 */
void iommu_group_release_dma_owner(struct iommu_group *group)
{
	int ret;

	mutex_lock(&group->mutex);
	if (WARN_ON(!group->owner_cnt || !group->owner))
		goto unlock_out;

	group->owner_cnt = 0;
	group->owner = NULL;
	ret = __iommu_group_set_domain(group, group->default_domain);
	WARN(ret, "iommu driver failed to attach the default domain");

unlock_out:
	mutex_unlock(&group->mutex);
}
EXPORT_SYMBOL_GPL(iommu_group_release_dma_owner);
#endif
