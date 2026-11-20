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

dnl #
dnl # v6.0-e33c267ab70d
dnl # mm: shrinkers: provide shrinkers with names
dnl #
AC_DEFUN([AC_REGISTER_SHRINKER_ARG2_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/shrinker.h>
		],[
			struct shrinker s = { 0 };
			register_shrinker(&s, "test");
		],[
		],[
			AC_DEFINE([BPM_REGISTER_SHRINKER_ARG2_NOT_PRESENT], 1,
				[register_shrinker second argument is not present])
		])
	])
])
