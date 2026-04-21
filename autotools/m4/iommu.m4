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
