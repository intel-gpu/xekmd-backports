// SPDX-License-Identifier: GPL-2.0
/*
 * PCI Express I/O Virtualization (IOV) support
 *   Single Root IOV 1.0
 *   Address Translation Service 1.0
 *
 * Copyright (C) 2009 Intel Corporation, Yu Zhao <yu.zhao@intel.com>
 */

#include <linux/sizes.h>
#include <linux/log2.h>
#include <asm/div64.h>
#include <linux/pci.h>

#ifdef BPM_PCI_IOV_VF_BAR_FUNCTIONS_NOT_PRESENT
/**
 * pci_iov_vf_bar_set_size - set a new size for a VF BAR
 * @dev: the PCI device
 * @resno: the resource number
 * @size: new size as defined in the spec (0=1MB, 31=128TB)
 *
 * Set the new size of a VF BAR that supports VF resizable BAR capability.
 * Unlike pci_resize_resource(), this does not cause the resource that
 * reserves the MMIO space (originally up to total_VFs) to be resized, which
 * means that following calls to pci_enable_sriov() can fail if the resources
 * no longer fit.
 *
 * Return: 0 on success, or negative on failure.
 */
int pci_iov_vf_bar_set_size(struct pci_dev *dev, int resno, int size)
{
	u32 sizes;

	sizes = pci_rebar_get_possible_sizes(dev, resno);
	if (!sizes)
		return -ENOTSUPP;

	if (!(sizes & BIT(size)))
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL(pci_iov_vf_bar_set_size);

/**
 * pci_iov_vf_bar_get_sizes - get VF BAR sizes allowing to create up to num_vfs
 * @dev: the PCI device
 * @resno: the resource number
 * @num_vfs: number of VFs
 *
 * Get the sizes of a VF resizable BAR that can accommodate @num_vfs within
 * the currently assigned size of the resource @resno.
 *
 * Return: A bitmask of sizes in format defined in the spec (bit 0=1MB,
 * bit 31=128TB).
 */
u32 pci_iov_vf_bar_get_sizes(struct pci_dev *dev, int resno, int num_vfs)
{
	u64 vf_len = pci_resource_len(dev, resno);
	u32 sizes;

	if (!num_vfs)
		return 0;

	do_div(vf_len, num_vfs);
	sizes = (roundup_pow_of_two(vf_len + 1) - 1) >> ilog2(SZ_1M);

	return 0;
}
EXPORT_SYMBOL(pci_iov_vf_bar_get_sizes);
#endif
