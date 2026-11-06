dnl #
dnl #  v6.16 - 285e871884ff
dnl #  mm/hmm: let users to tag specific PFN with DMA mapped bit
dnl #

AC_DEFUN([AC_HMM_PFN_TO_PHYS_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/hmm.h>
		], [
			(void)hmm_pfn_to_phys(0);
		], [
		], [
			AC_DEFINE(BPM_HMM_PFN_TO_PHYS_NOT_PRESENT, 1,
				  [hmm_pfn_to_phys() is not available])
		])
	])
])
