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

#ifdef BPM_PCI_RESIZE_RESOURCE_ARG4_NOT_PRESENT
#define pci_resize_resource(pdev, i, size, exclude_bars) \
	pci_resize_resource(pdev, i, size)
#endif

#ifdef BPM_PCI_REBAR_SIZE_SUPPORTED_NOT_PRESENT
#define SZ_128T				(1ULL << 47)
#define PCI_REBAR_MIN_SIZE		((resource_size_t)SZ_1M)
bool pci_rebar_size_supported(struct pci_dev *pdev, int bar, int size);
#endif

#ifdef BPM_PCI_REBAR_SIZE_TO_BYTES_NOT_PRESENT
resource_size_t pci_rebar_size_to_bytes(int size);
#endif

#ifdef BPM_PCI_REBAR_GET_MAX_SIZE_NOT_PRESENT
int pci_rebar_get_max_size(struct pci_dev *pdev, int bar);
#endif

#endif /* _BACKPORT_LINUX_PCI_H */
