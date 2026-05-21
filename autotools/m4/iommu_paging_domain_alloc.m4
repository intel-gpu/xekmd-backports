dnl #
dnl # v6.11-a27bf2743cb8
dnl # iommu: Add iommu_paging_domain_alloc() interface
dnl #
AC_DEFUN([AC_IOMMU_PAGING_DOMAIN_ALLOC_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/iommu.h>
		],[
			struct iommu_domain *domain;

			domain = iommu_paging_domain_alloc(NULL);
			(void)domain;
		],[
		],[
			AC_DEFINE(BPM_IOMMU_PAGING_DOMAIN_ALLOC_NOT_PRESENT, 1,
				[iommu_paging_domain_alloc() is not available])
		])
	])
])
