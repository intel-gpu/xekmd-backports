dnl #
dnl # 437cb3ded25
dnl # cpumask: Introduce cpumask_weighted_or()
dnl #
AC_DEFUN([AC_BITMAP_WEIGHTED_OR_NOT_PRESENT], [
		AC_KERNEL_DO_BACKGROUND([
			AC_KERNEL_TRY_COMPILE([
			#include <linux/bitmap.h>
			],[
			unsigned long dst, src1 = 1, src2 = 2;
			unsigned int weight = bitmap_weighted_or(&dst, &src1, &src2, 32);
			(void)weight;
			],[
			],[
			AC_DEFINE([BPM_BITMAP_WEIGHTED_OR_NOT_PRESENT], 1,
				[bitmap_weighted_or() is not present in kernel headers])
			])
		])
])

dnl #
dnl # 95d324fb1b
dnl # bitmap: add test_zero_nbits()
dnl #
AC_DEFUN([AC_UNDERSCORE_BITMAP_WEIGHTED_OR_NOT_PRESENT], [
		AC_KERNEL_DO_BACKGROUND([
			AC_KERNEL_TRY_COMPILE_SYMBOL([
			#include <linux/bitmap.h>
			],[
			unsigned long dst, src1 = 1, src2 = 2;
			unsigned int weight = bitmap_weighted_or(&dst, &src1, &src2, 32);
			(void)weight;
			],[__bitmap_weighted_or],[lib/bitmap.c],[
			],[
			AC_DEFINE([BPM_UNDERSCORE_BITMAP_WEIGHTED_OR_NOT_PRESENT], 1,
				[bitmap_weighted_or() is not present in kernel headers])
			])
		])
])
