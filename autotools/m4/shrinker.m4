dnl #
dnl # v6.7-c42d50aefd17
dnl # mm: shrinker: add infrastructure for dynamically allocating shrinker
dnl #
AC_DEFUN([AC_SHRINKER_ALLOC_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/shrinker.h>
		],[
			struct shrinker *s;
			s = shrinker_alloc(0, "test");
		],[
		],[
			AC_DEFINE([BPM_SHRINKER_ALLOC_NOT_PRESENT], 1,
				[shrinker_alloc/register/free API not present])
		])
	])
])
