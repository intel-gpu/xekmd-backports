/* SPDX-License-Identifier: GPL-2.0 */
/*
 * irq_domain - IRQ translation domains
 *
 * Translation infrastructure between hw and linux irq numbers.  This is
 * helpful for interrupt controllers to implement mapping between hardware
 * irq numbers and the Linux irq number space.
 *
 * irq_domains also have hooks for translating device tree or other
 * firmware interrupt representations into a hardware irq number that
 * can be mapped back to a Linux irq number without any extra platform
 * support code.
 *
 * Interrupt controller "domain" data structure. This could be defined as a
 * irq domain controller. That is, it handles the mapping between hardware
 * and virtual interrupt numbers for a given interrupt domain. The domain
 * structure is generally created by the PIC code for a given PIC instance
 * (though a domain can cover more than one PIC if they have a flat number
 * model). It's the domain callbacks that are responsible for setting the
 * irq_chip on a given irq_desc after it's been mapped.
 *
 * The host code and data structures use a fwnode_handle pointer to
 * identify the domain. In some cases, and in order to preserve source
 * code compatibility, this fwnode pointer is "upgraded" to a DT
 * device_node. For those firmware infrastructures that do not provide
 * a unique identifier for an interrupt controller, the irq_domain
 * code offers a fwnode allocator.
 */

#ifndef _BPM_IRQDOMAIN_H
#define _BPM_IRQDOMAIN_H

#include_next <linux/irqdomain.h>

#ifndef IRQ_DOMAIN_FLAG_ISOLATED_MSI
#define IRQ_DOMAIN_FLAG_ISOLATED_MSI 32
#endif

#ifndef IRQ_DOMAIN_FLAG_MSI_PARENT
#define IRQ_DOMAIN_FLAG_MSI_PARENT (1 << 8)
#endif

#ifndef IRQ_DOMAIN_FLAG_MSI_DEVICE
#define IRQ_DOMAIN_FLAG_MSI_DEVICE (1 << 9)
#endif

#ifdef BPM_IOMMU_GROUP_HAS_ISOLATED_MSI_NOT_PRESENT
bool irq_domain_check_msi_remap(void);
#endif

#endif
