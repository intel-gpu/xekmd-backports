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

#ifdef BPM_PCI_REBAR_SIZE_SUPPORTED_NOT_PRESENT
/*
 * v7.0 added pci_rebar_size_to_bytes, pci_rebar_size_supported,
 * pci_rebar_get_max_size, and pci_resize_resource gained a 4th arg.
 * Provide compat for 6.6.
 */
static inline u64 pci_rebar_size_to_bytes(int size)
{
	return (u64)1 << (size + 20);
}

static inline bool pci_rebar_size_supported(struct pci_dev *pdev,
					    int bar, int size)
{
	u32 sizes = pci_rebar_get_possible_sizes(pdev, bar);

	return sizes & BIT(size);
}

static inline int pci_rebar_get_max_size(struct pci_dev *pdev, int bar)
{
	u32 sizes = pci_rebar_get_possible_sizes(pdev, bar);

	if (!sizes)
		return -ENOTSUPP;
	return fls(sizes) - 1;
}
#endif /* BPM_PCI_REBAR_SIZE_SUPPORTED_NOT_PRESENT */

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
#endif /* BPM_PCI_IOV_GET_PF_DRVDATA_NOT_PRESENT  */

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

#ifdef BPM_PCI_IOV_VF_ID_NOT_PRESENT
#ifdef CONFIG_PCI_IOV
int pci_iov_vf_id(struct pci_dev *dev);
#else
static inline int pci_iov_vf_id(struct pci_dev *dev)
{
	return -ENOSYS;
}
#endif
#endif

#endif /* _BACKPORT_LINUX_PCI_H */
