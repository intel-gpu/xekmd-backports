dnl #
dnl #  v6.12 - d51e783c17ba
dnl #  lsm: count the LSMs enabled at compile time
dnl #

AC_DEFUN([AC_COUNT_ARGS_15_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#ifdef HAVE_LINUX_ARGS_H
			#include <linux/args.h>
			#else
			#include <linux/kernel.h>
			#endif
		], [
			_Static_assert(COUNT_ARGS(1, 2, 3, 4, 5, 6, 7, 8,
						 9, 10, 11, 12, 13, 14, 15) == 15,
				       "COUNT_ARGS must support 15 arguments");
		], [
		], [
			AC_DEFINE(BPM_COUNT_ARGS_15_NOT_PRESENT, 1,
				  [COUNT_ARGS() does not support 15 arguments])
		])
	])
])
