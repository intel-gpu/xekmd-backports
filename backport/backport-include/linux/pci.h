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

#endif /* _BACKPORT_LINUX_PCI_H */
