/* SPDX-License-Identifier: GPL-2.0 */
/*
 */

#include <linux/pci.h>
#include <linux/log2.h>
#include <linux/sizes.h>

#ifdef BPM_PCI_REBAR_SIZE_SUPPORTED_NOT_PRESENT

/**
 * pci_rebar_size_supported - check if size is supported for BAR
 * @pdev: PCI device
 * @bar: BAR to check
 * @size: encoded size as defined in the PCIe spec (0=1MB, 31=128TB)
 *
 * Return: %true if @bar is resizable and @size is supported, otherwise
 *	   %false.
 */
bool pci_rebar_size_supported(struct pci_dev *pdev, int bar, int size)
{
	u64 sizes = pci_rebar_get_possible_sizes(pdev, bar);

	if (size < 0 || size > ilog2(SZ_128T) - ilog2(PCI_REBAR_MIN_SIZE))
		return false;

	return BIT(size) & sizes;
}
EXPORT_SYMBOL_GPL(pci_rebar_size_supported);

#endif

#ifdef BPM_PCI_REBAR_SIZE_TO_BYTES_NOT_PRESENT

/**
 * pci_rebar_size_to_bytes - convert rebar size encoding to bytes
 * @size: encoded size as defined in the PCIe spec (0=1MB, 31=128TB)
 *
 * Return: size in bytes
 */
resource_size_t pci_rebar_size_to_bytes(int size)
{
	return 1ULL << (size + ilog2(PCI_REBAR_MIN_SIZE));
}
EXPORT_SYMBOL_GPL(pci_rebar_size_to_bytes);

#endif

#ifdef BPM_PCI_REBAR_GET_MAX_SIZE_NOT_PRESENT

/**
 * pci_rebar_get_max_size - get the maximum supported size of a BAR
 * @pdev: PCI device
 * @bar: BAR to query
 *
 * Get the largest supported size of a resizable BAR as a size.
 *
 * Return: the encoded maximum BAR size as defined in the PCIe spec
 *	   (0=1MB, 31=128TB), or %-NOENT on error.
 */
int pci_rebar_get_max_size(struct pci_dev *pdev, int bar)
{
	u64 sizes;

	sizes = pci_rebar_get_possible_sizes(pdev, bar);
	if (!sizes)
		return -ENOENT;

	return __fls(sizes);
}
EXPORT_SYMBOL_GPL(pci_rebar_get_max_size);

#endif
