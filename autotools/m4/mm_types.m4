dnl #
dnl # v7.0-rc1 - bae0ba7c7c0a0
dnl # mm: add basic VMA flag operation helper functions
dnl #
AC_DEFUN([AC_VMA_FLAGS_T_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mm_types.h>
		],[
			vma_flags_t flags = { };
		],[
		],[
			AC_DEFINE(BPM_VMA_FLAGS_T_NOT_PRESENT, 1,
				[vma_flags_t type is not available])
		])
	])
])
