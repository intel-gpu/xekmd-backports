dnl #
dnl # v6.3-efc30a8f15a7
dnl # iommu: Add iommu_group_has_isolated_msi()
dnl #
AC_DEFUN([AC_IOMMU_GROUP_HAS_ISOLATED_MSI_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/iommu.h>
		],[
			iommu_group_has_isolated_msi((struct iommu_group *)NULL);
		],[
		],[
			AC_DEFINE(BPM_IOMMU_GROUP_HAS_ISOLATED_MSI_NOT_PRESENT, 1,
				[iommu_group_has_isolated_msi() is not available])
		])
	])
])
