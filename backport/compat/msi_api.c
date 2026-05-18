// SPDX-License-Identifier: GPL-2.0
/*
 * PCI MSI/MSI-X — Exported APIs for device drivers
 *
 * Copyright (C) 2003-2004 Intel
 * Copyright (C) Tom Long Nguyen (tom.l.nguyen@intel.com)
 * Copyright (C) 2016 Christoph Hellwig.
 * Copyright (C) 2022 Linutronix GmbH
 */
#include <linux/pci.h>
#include <linux/export.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/msi.h>

#ifdef BPM_PCI_MSIX_ALLOC_IRQ_NOT_PRESENT
#ifdef CONFIG_PCI_MSI

/*
 * Per device interrupt domain related constants.
 */
enum msi_domain_ids {
	MSI_DEFAULT_DOMAIN,
	MSI_SECONDARY_DOMAIN,
	MSI_MAX_DEVICE_IRQDOMAINS,
};

enum support_mode {
	ALLOW_LEGACY,
	DENY_LEGACY,
};

#define IRQ_DOMAIN_FLAG_MSI_PARENT (1 << 8)
#define MSI_FLAG_PCI_MSIX_ALLOC_DYN (1 << 20)

/**
 * pci_msi_domain_supports - Check for support of a particular feature flag
 * @pdev:		The PCI device to operate on
 * @feature_mask:	The feature mask to check for (full match)
 * @mode:		If ALLOW_LEGACY this grants the feature when there is no irq domain
 *			associated to the device. If DENY_LEGACY the lack of an irq domain
 *			makes the feature unsupported
 */
bool pci_msi_domain_supports(struct pci_dev *pdev, unsigned int feature_mask,
			     enum support_mode mode)
{
	struct msi_domain_info *info;
	struct irq_domain *domain;
	unsigned int supported;

	domain = dev_get_msi_domain(&pdev->dev);

	if (!domain || !irq_domain_is_hierarchy(domain))
		return mode == ALLOW_LEGACY;

	if (!irq_domain_is_msi_parent(domain)) {
		/*
		 * For "global" PCI/MSI interrupt domains the associated
		 * msi_domain_info::flags is the authoritive source of
		 * information.
		 */
		info = domain->host_data;
		supported = info->flags;
	} else {
		/*
		 * For MSI parent domains the supported feature set
		 * is avaliable in the parent ops. This makes checks
		 * possible before actually instantiating the
		 * per device domain because the parent is never
		 * expanding the PCI/MSI functionality.
		 */
		supported = domain->msi_parent_ops->supported_flags;
	}

	return (supported & feature_mask) == feature_mask;
}

/**
 * pci_msix_can_alloc_dyn - Query whether dynamic allocation after enabling
 *                          MSI-X is supported
 *
 * @dev: PCI device to operate on
 *
 * Return: True if supported, false otherwise
 */
bool pci_msix_can_alloc_dyn(struct pci_dev *dev)
{
        if (!dev->msix_cap)
                return false;

	return pci_msi_domain_supports(dev, MSI_FLAG_PCI_MSIX_ALLOC_DYN, DENY_LEGACY);
}
EXPORT_SYMBOL_GPL(pci_msix_can_alloc_dyn);

/**
 * pci_msix_alloc_irq_at - Allocate an MSI-X interrupt after enabling MSI-X
 *			   at a given MSI-X vector index or any free vector index
 *
 * @dev:	PCI device to operate on
 * @index:	Index to allocate. If @index == MSI_ANY_INDEX this allocates
 *		the next free index in the MSI-X table
 * @affdesc:	Optional pointer to an affinity descriptor structure. NULL otherwise
 *
 * Return: A struct msi_map
 *
 *	On success msi_map::index contains the allocated index (>= 0) and
 *	msi_map::virq contains the allocated Linux interrupt number (> 0).
 *
 *	On fail msi_map::index contains the error code and msi_map::virq
 *	is set to 0.
 */

struct msi_map pci_msix_alloc_irq_at(struct pci_dev *dev, unsigned int index,
				     const struct irq_affinity_desc *affdesc)
{
	struct msi_map map = { .index = -ENOTSUPP };

	if (!dev->msix_enabled)
		return map;

	if (!pci_msix_can_alloc_dyn(dev))
		return map;

	return map;
}
EXPORT_SYMBOL_GPL(pci_msix_alloc_irq_at);

/**
 * irq_domain_instantiate() - Instantiate a new irq domain data structure
 * @info: Domain information pointer pointing to the information for this domain
 *
 * Return: A pointer to the instantiated irq domain or an ERR_PTR value.
 */
struct irq_domain *irq_domain_instantiate(const struct irq_domain_info *info)
{
        int err = 0;
        return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(irq_domain_instantiate);

#endif
#endif
