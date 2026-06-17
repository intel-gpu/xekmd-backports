# SPDX-License-Identifier: GPL-2.0-only

vfio-pci-core-y := vfio_pci_core.o vfio_pci_intrs.o vfio_pci_rdwr.o vfio_pci_config.o
vfio-pci-core-$(CPTCFG_VFIO_PCI_ZDEV_KVM) += vfio_pci_zdev.o
obj-$(CPTCFG_VFIO_PCI_CORE) += vfio-pci-core.o

vfio-pci-y := vfio_pci.o
vfio-pci-$(CPTCFG_VFIO_PCI_IGD) += vfio_pci_igd.o
obj-$(CPTCFG_VFIO_PCI) += vfio-pci.o

obj-$(CPTCFG_MLX5_VFIO_PCI)           += mlx5/

obj-$(CPTCFG_HISI_ACC_VFIO_PCI) += hisilicon/

obj-$(CPTCFG_PDS_VFIO_PCI) += pds/

obj-$(CPTCFG_VIRTIO_VFIO_PCI) += virtio/

obj-$(CPTCFG_NVGRACE_GPU_VFIO_PCI) += nvgrace-gpu/

obj-$(CPTCFG_QAT_VFIO_PCI) += qat/

obj-$(CPTCFG_XE_VFIO_PCI) += xe/
