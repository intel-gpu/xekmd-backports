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

//#ifdef TRUE
#ifdef CONFIG_PCI_MSI

/**
 * pci_msix_can_alloc_dyn - Query whether dynamic allocation after enabling
 *                          MSI-X is supported
 *
 * @dev:        PCI device to operate on
 *
 * Return: True if supported, false otherwise
 */
bool pci_msix_can_alloc_dyn(struct pci_dev *dev)
{
        if (!dev->msix_cap)
                return false;

	return true;
//        return pci_msi_domain_supports(dev, MSI_FLAG_PCI_MSIX_ALLOC_DYN, DENY_LEGACY);
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
	struct msi_map map = { .index = -ENOSYS, .virq = -ENOSYS };
//	struct msi_map map = { .index = -ENOTSUPP };
	return map;
/*
	if (!dev->msix_enabled)
		return map;

	if (!pci_msix_can_alloc_dyn(dev))
		return map;

	return msi_domain_alloc_irq_at(&dev->dev, MSI_DEFAULT_DOMAIN, index, affdesc, NULL);*/
}
EXPORT_SYMBOL_GPL(pci_msix_alloc_irq_at);

//#endif
#endif
