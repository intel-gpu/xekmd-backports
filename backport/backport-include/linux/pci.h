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

#ifndef BACKPORT_STRUCT_PCI_SRIOV_DEFINED
#define BACKPORT_STRUCT_PCI_SRIOV_DEFINED
/* Single Root I/O Virtualization */
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
#endif

#endif /* _BACKPORT_LINUX_PCI_H */
