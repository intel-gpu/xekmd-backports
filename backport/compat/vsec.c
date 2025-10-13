// SPDX-License-Identifier: GPL-2.0
/*
 * Intel Vendor Specific Extended Capabilities auxiliary bus driver
 *
 * Copyright (c) 2021, Intel Corporation.
 * All Rights Reserved.
 *
 * Author: David E. Box <david.e.box@linux.intel.com>
 *
 * This driver discovers and creates auxiliary devices for Intel defined PCIe
 * "Vendor Specific" and "Designated Vendor Specific" Extended Capabilities,
 * VSEC and DVSEC respectively. The driver supports features on specific PCIe
 * endpoints that exist primarily to expose them.
 */

#include <linux/pci.h>
#include <linux/export.h>
#include <backport/backport.h>

#ifdef BPM_INTEL_VSEC_REGISTER_NOT_PRESENT

#include <linux/intel_vsec.h>

void intel_vsec_register(struct pci_dev *pdev,
                         struct intel_vsec_platform_info *info)
{
        if (!pdev || !info || !info->headers)
                return;

}
EXPORT_SYMBOL_GPL(intel_vsec_register);

#endif /* BPM_INTEL_VSEC_REGISTER_NOT_PRESENT */
