dnl #
dnl # v6.3-1369459b2e21
dnl # iommu: Add a gfp parameter to iommu_map()
dnl #
AC_DEFUN([AC_IOMMU_MAP_GFP_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/iommu.h>
		],[
			iommu_map((struct iommu_domain *)NULL, 0, 0, 0, 0, GFP_KERNEL);
		],[
		],[
			AC_DEFINE(BPM_IOMMU_MAP_GFP_NOT_PRESENT, 1,
				[iommu_map() does not have gfp parameter])
		])
	])
])
