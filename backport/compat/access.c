// SPDX-License-Identifier: GPL-2.0
#include <linux/pci.h>

#ifdef BPM_PCI_CLEAR_AND_SET_CONFIG_DWORD_NOT_PRESENT
void pci_clear_and_set_config_dword(const struct pci_dev *dev, int pos,
				    u32 clear, u32 set)
{
	u32 val;

	pci_read_config_dword(dev, pos, &val);
	val &= ~clear;
	val |= set;
	pci_write_config_dword(dev, pos, val);
}
EXPORT_SYMBOL(pci_clear_and_set_config_dword);
#endif
