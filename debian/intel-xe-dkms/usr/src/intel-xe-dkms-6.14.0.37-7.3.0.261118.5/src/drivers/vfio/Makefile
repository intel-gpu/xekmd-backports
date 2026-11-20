# SPDX-License-Identifier: GPL-2.0
obj-$(CPTCFG_VFIO) += vfio.o

vfio-y += vfio_main.o
vfio-$(CPTCFG_VFIO_DEVICE_CDEV) += device_cdev.o
vfio-$(CPTCFG_VFIO_GROUP) += group.o
vfio-$(CONFIG_IOMMUFD) += iommufd.o
vfio-$(CPTCFG_VFIO_CONTAINER) += container.o
vfio-$(CPTCFG_VFIO_VIRQFD) += virqfd.o
vfio-$(CPTCFG_VFIO_DEBUGFS) += debugfs.o

obj-$(CPTCFG_VFIO_IOMMU_TYPE1) += vfio_iommu_type1.o
obj-$(CPTCFG_VFIO_IOMMU_SPAPR_TCE) += vfio_iommu_spapr_tce.o
obj-$(CPTCFG_VFIO_PCI_CORE) += pci/
obj-$(CPTCFG_VFIO_PLATFORM_BASE) += platform/
obj-$(CPTCFG_VFIO_MDEV) += mdev/
obj-$(CPTCFG_VFIO_FSL_MC) += fsl-mc/
obj-$(CPTCFG_VFIO_CDX) += cdx/
