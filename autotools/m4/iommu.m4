dnl #
dnl # v5.19 - ed36d04e8f8d
dnl # iommu: Introduce device_iommu_capable()
dnl #
AC_DEFUN([AC_DEVICE_IOMMU_CAPABLE_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/iommu.h>
		],[
			device_iommu_capable((struct device *)NULL, 0);
		],[
		],[
			AC_DEFINE(BPM_DEVICE_IOMMU_CAPABLE_NOT_PRESENT, 1,
				[device_iommu_capable() is not available])
		])
	])
])

dnl #
dnl # v5.19 - 1ea2a07a532b
dnl # iommu: Add DMA ownership management interfaces
dnl #
AC_DEFUN([AC_IOMMU_GROUP_CLAIM_DMA_OWNER_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/iommu.h>
		],[
			iommu_group_claim_dma_owner((struct iommu_group *)NULL, NULL);
		],[
		],[
			AC_DEFINE(BPM_IOMMU_GROUP_CLAIM_DMA_OWNER_NOT_PRESENT, 1,
				[iommu_group_claim_dma_owner() is not available])
		])
	])
])

dnl #
dnl # v6.11 - a27bf2743cb8
dnl # iommu: Add iommu_paging_domain_alloc() interface
dnl #
AC_DEFUN([AC_IOMMU_PAGING_DOMAIN_ALLOC_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/iommu.h>
		],[
			iommu_paging_domain_alloc((struct device *)NULL);
		],[
		],[
			AC_DEFINE(BPM_IOMMU_PAGING_DOMAIN_ALLOC_NOT_PRESENT, 1,
				[iommu_paging_domain_alloc() is not available])
		])
	])
])
