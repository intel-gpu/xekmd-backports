dnl #
dnl # v5.18- 5f3cec21f6d5
dnl # overflow: add range_overflows() and range_end_overflows()
dnl #
AC_DEFUN([AC_RANGE_OVERFLOWS_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <drm/drm_buddy.h>
		],[
			(void)range_overflows(0, 4096, 8192);
		],[
		],[
			AC_DEFINE(BPM_RANGE_OVERFLOWS_NOT_PRESENT, 1,
				[range_overflows() is not provided by the kernel])
		])
	])
])
