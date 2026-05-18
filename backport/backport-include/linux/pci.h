/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BACKPORT_LINUX_PCI_H
#define _BACKPORT_LINUX_PCI_H
#include <linux/sizes.h>
#include <linux/log2.h>
#include <asm/div64.h>
#include_next <linux/pci.h>

#ifdef BPM_PCI_IOV_VF_BAR_FUNCTIONS_NOT_PRESENT
int pci_iov_vf_bar_set_size(struct pci_dev *dev, int resno, int size);
u32 pci_iov_vf_bar_get_sizes(struct pci_dev *dev, int resno, int num_vfs);
#endif

#ifdef BPM_PCI_IOV_GET_PF_DRVDATA_NOT_PRESENT
#ifdef CONFIG_PCI_IOV
void *pci_iov_get_pf_drvdata(struct pci_dev *dev, struct pci_driver *pf_driver);
#else
static inline void *pci_iov_get_pf_drvdata(struct pci_dev *dev,
					   struct pci_driver *pf_driver)
{
	return ERR_PTR(-EINVAL);
}
#endif
#endif

#ifdef BPM_PCI_DEV_FOR_EACH_RESOURCE_NOT_PRESENT
#define pci_dev_for_each_resource(pdev, res, i) \
	for ((i) = 0; (i) < PCI_NUM_RESOURCES && \
	     (((res) = &((pdev)->resource[(i)])), 1); (i)++)
#endif

#ifdef BPM_PCI_MSIX_ALLOC_IRQ_NOT_PRESENT
struct msi_map {
        int     index;
        int     virq;
};

#ifdef CONFIG_PCI_MSI
struct msi_map pci_msix_alloc_irq_at(struct pci_dev *dev, unsigned int index,
                                     const struct irq_affinity_desc *affdesc);
bool pci_msix_can_alloc_dyn(struct pci_dev *dev);
#else
static inline struct msi_map pci_msix_alloc_irq_at(struct pci_dev *dev, unsigned int index,
                                                   const struct irq_affinity_desc *affdesc)
{
        struct msi_map map = { .index = -ENOSYS, };

        return map;
}
static inline bool pci_msix_can_alloc_dyn(struct pci_dev *dev)
{ return false; }
#endif
#endif

#endif /* _BACKPORT_LINUX_PCI_H */
