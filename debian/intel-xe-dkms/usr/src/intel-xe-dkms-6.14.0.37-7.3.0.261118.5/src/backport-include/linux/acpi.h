/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BACKPORT_LINUX_ACPI_H
#define __BACKPORT_LINUX_ACPI_H

#include_next <linux/acpi.h>

#ifdef BPM_ACPI_DEV_FOR_EACH_CHILD_NOT_PRESENT

struct backport_acpi_dev_walk_context {
	int (*fn)(struct acpi_device *adev, void *data);
	void *data;
};

static inline int backport_acpi_dev_for_one_check(struct device *dev, void *context)
{
	struct backport_acpi_dev_walk_context *adwc = context;

	return adwc->fn(to_acpi_device(dev), adwc->data);
}

static inline int acpi_dev_for_each_child(struct acpi_device *adev,
					  int (*fn)(struct acpi_device *adev, void *data),
					  void *data)
{
	struct backport_acpi_dev_walk_context adwc = {
		.fn = fn,
		.data = data,
	};

	return device_for_each_child(&adev->dev, &adwc,
				     backport_acpi_dev_for_one_check);
}

#endif

#endif /* __BACKPORT_LINUX_ACPI_H */
