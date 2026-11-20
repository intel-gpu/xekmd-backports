// SPDX-License-Identifier: GPL-2.0
/*
 * PCI Express I/O Virtualization (IOV) support
 *   Single Root IOV 1.0
 *   Address Translation Service 1.0
 *
 * Copyright (C) 2009 Intel Corporation, Yu Zhao <yu.zhao@intel.com>
 */

#include <linux/pci.h>

#ifdef BPM_PCI_IOV_VF_ID_NOT_PRESENT
struct pci_sriov {
        int             pos;            /* Capability position */
        int             nres;           /* Number of resources */
        u32             cap;            /* SR-IOV Capabilities */
        u16             ctrl;           /* SR-IOV Control */
        u16             total_VFs;      /* Total VFs associated with the PF */
        u16             initial_VFs;    /* Initial VFs associated with the PF */
        u16             num_VFs;        /* Number of VFs available */
        u16             offset;         /* First VF Routing ID offset */
        u16             stride;         /* Following VF stride */
        u16             vf_device;      /* VF device ID */
        u32             pgsz;           /* Page size for BAR alignment */
        u8              link;           /* Function Dependency Link */
        u8              max_VF_buses;   /* Max buses consumed by VFs */
        u16             driver_max_VFs; /* Max num VFs driver supports */
        struct pci_dev  *dev;           /* Lowest numbered PF */
        struct pci_dev  *self;          /* This PF */
        u32             class;          /* VF device */
        u8              hdr_type;       /* VF header type */
        u16             subsystem_vendor; /* VF subsystem vendor */
        u16             subsystem_device; /* VF subsystem device */
        resource_size_t barsz[PCI_SRIOV_NUM_BARS];      /* VF BAR size */
        bool            drivers_autoprobe; /* Auto probing of VFs by driver */
};

int pci_iov_vf_id(struct pci_dev *dev)
{
	struct pci_dev *pf;

	if (!dev->is_virtfn)
		return -EINVAL;

	pf = pci_physfn(dev);
	return (pci_dev_id(dev) - (pci_dev_id(pf) + pf->sriov->offset)) /
	       pf->sriov->stride;
}
EXPORT_SYMBOL_GPL(pci_iov_vf_id);
#endif
