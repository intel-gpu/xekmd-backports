dnl #
dnl # v6.6 - 3e60f3c1a9a0 (approx)
dnl # iommu: Add iommu_domain_ops::enforce_cache_coherency()
dnl #
AC_DEFUN([AC_ENFORCE_CACHE_COHERENCY_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/iommu.h>
		],[
			static const struct iommu_domain_ops ops = {
				.enforce_cache_coherency = NULL,
			};
			(void)ops;
		],[
		],[
			AC_DEFINE(BPM_ENFORCE_CACHE_COHERENCY_NOT_PRESENT, 1,
				[struct iommu_domain_ops does not have enforce_cache_coherency member])
		])
	])
])
