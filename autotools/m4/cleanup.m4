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

dnl #
dnl # v7.0-rc1 - e4ab322fbaaaf
dnl # cleanup: Add conditional guard support
dnl #
dnl #
AC_DEFUN([AC_DEFINE_GUARD_COND_4_ARGS_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/cleanup.h>
		],[
			DEFINE_GUARD_COND(test_guard, _test, 1, _RET >= 0);
		],[
		],[
			AC_DEFINE(BPM_DEFINE_GUARD_COND_4_ARGS_NOT_PRESENT, 1,
				[DEFINE_GUARD_COND with 4 arguments is not available])
		])
	])
])

