dnl #
dnl # v6.7-53f0b020218f
dnl # vfio/iova_bitmap: Export more API symbols
dnl #
AC_DEFUN([AC_IOVA_BITMAP_SYMBOL_EXPORTS_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE_SYMBOL([
			#include <linux/iova_bitmap.h>
		],[
			struct iova_bitmap *bitmap = NULL;

			bitmap = iova_bitmap_alloc(0, 0, 0, NULL);
		],[iova_bitmap_alloc],
		[drivers/vfio/iova_bitmap.c],[
		],[
			AC_DEFINE(BPM_IOVA_BITMAP_SYMBOL_EXPORTS_NOT_PRESENT, 1,
				[iova_bitmap_alloc(), iova_bitmap_free(), and iova_bitmap_for_each() are not exported])
		])
	])
])
