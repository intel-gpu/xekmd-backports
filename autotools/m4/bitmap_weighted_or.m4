dnl #
dnl # ac679a6e0fcc
dnl # drm/xe: switch xe_pagefault_queue_init() to using bitmap_weighted_or()
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
				[bitmap_weighted_or() is not available])
			])
		])
])
