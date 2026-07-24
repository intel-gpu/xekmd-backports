#include <linux/slab.h>
#include <linux/string.h>
#include <linux/device.h>
#include <linux/pci.h>

#ifdef BPM_DEVICE_SET_DRIVER_OVERRIDE_NOT_PRESENT
/*
 * device_set_driver_override() was added in v6.5 (6265539776a0). Provide a
 * minimal equivalent for older kernels.
 *
 * driver_override was only unified into struct device in v5.19; before that
 * (e.g. 5.15) it lives on the bus-specific struct. This module only builds the
 * VFIO PCI path, so on those kernels store into struct pci_dev.driver_override.
 */
int device_set_driver_override(struct device *dev, const char *s)
{
	char *new = NULL;
	const char *old;
	size_t len;

	if (!s)
		return -EINVAL;

	/*
	 * The stored value will be used in sysfs show callback (sysfs_emit()),
	 * which has a length limit of PAGE_SIZE and adds a trailing newline.
	 * Thus we can store one character less to avoid truncation during sysfs
	 * show.
	 */
	len = strlen(s);
	if (len >= (PAGE_SIZE - 1))
		return -EINVAL;

	/* Handle trailing newline */
	if (len) {
		char *cp;

		cp = strnchr(s, len, '\n');
		if (cp)
			len = cp - s;
	}

	/*
	 * If empty string or "\n" passed, new remains NULL, clearing
	 * the driver_override.
	 */
	if (len) {
		new = kstrndup(s, len, GFP_KERNEL);
		if (!new)
			return -ENOMEM;
	}

	device_lock(dev);
#ifdef BPM_STRUCT_DEVICE_DRIVER_OVERRIDE_NOT_PRESENT
	old = to_pci_dev(dev)->driver_override;
	to_pci_dev(dev)->driver_override = new;
#else
	old = dev->driver_override;
	dev->driver_override = new;
#endif
	device_unlock(dev);

	kfree(old);

	return 0;
}
EXPORT_SYMBOL_GPL(device_set_driver_override);
#endif
