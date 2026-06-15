/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2021 Intel Corporation
 */

#ifndef _XE_PCI_H_
#define _XE_PCI_H_

struct pci_dev;

struct xe_device *xe_pci_get_pf(struct pci_dev *pdev);
int xe_register_pci_driver(void);
void xe_unregister_pci_driver(void);

#endif
