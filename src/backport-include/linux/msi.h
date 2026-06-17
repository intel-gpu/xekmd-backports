/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BPM_MSI_H
#define BPM_MSI_H

#include_next <linux/msi.h>

#ifdef BPM_PCI_MSIX_ALLOC_IRQ_NOT_PRESENT
/**
 * struct msi_parent_ops - MSI parent domain callbacks and configuration info
 *
 * @supported_flags:	Required: The supported MSI flags of the parent domain
 * @prefix:		Optional: Prefix for the domain and chip name
 * @init_dev_msi_info:	Required: Callback for MSI parent domains to setup parent
 *			domain specific domain flags, domain ops and interrupt chip
 *			callbacks when a per device domain is created.
 */
struct msi_parent_ops {
	u32		supported_flags;
	const char	*prefix;
	bool		(*init_dev_msi_info)(struct device *dev, struct irq_domain *domain,
					     struct irq_domain *msi_parent_domain,
					     struct msi_domain_info *msi_child_info);
};
#endif
#endif
