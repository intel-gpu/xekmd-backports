dnl #
dnl # v6.6-051ddcfeb1bd
dnl # mm: move PMD_ORDER to pgtable.h
dnl #
AC_DEFUN([AC_PMD_ORDER_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/pgtable.h>
		],[
			unsigned int order = PMD_ORDER;
			(void)order;
		],[
		],[
			AC_DEFINE(BPM_PMD_ORDER_NOT_PRESENT, 1,
				[PMD_ORDER macro is not available in linux/pgtable.h])
		])
	])
])
