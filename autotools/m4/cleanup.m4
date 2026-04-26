dnl #
dnl # v7.0-rc1 - 857d18f23ab1
dnl # cleanup: Introduce ACQUIRE() and ACQUIRE_ERR() for conditional locks
dnl #
dnl #
AC_DEFUN([AC_ACQUIRE_MACRO_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/cleanup.h>
		],[
			ACQUIRE(mutex, m);
		],[
		],[
			AC_DEFINE(BPM_ACQUIRE_MACRO_NOT_PRESENT, 1,
				[ACQUIRE macro is not available])
		])
	])
])
