dnl #
dnl # v6.14-d1fd97291423
dnl # ktime: Add us_to_ktime()
dnl #
AC_DEFUN([AC_US_TO_KTIME_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/ktime.h>
		],[
			us_to_ktime(0);
		],[
		],[
			AC_DEFINE(BPM_US_TO_KTIME_NOT_PRESENT, 1,
				[us_to_ktime() function is not available])
		])
	])
])
