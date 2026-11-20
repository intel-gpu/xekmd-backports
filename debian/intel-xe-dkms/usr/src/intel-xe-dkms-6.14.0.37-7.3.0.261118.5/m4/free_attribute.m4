dnl #
dnl # v6.9 - d12a82848eac
dnl # bitmap: Define a cleanup function for bitmaps
dnl #
AC_DEFUN([AC_FREE_ATTRIBUTE_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/slab.h>
		],[
			unsigned long *bitmap __free(bitmap) = bitmap_zalloc(1, GFP_KERNEL);
			(void)bitmap;
		],[
		],[
			AC_DEFINE(BPM_FREE_ATTRIBUTE_NOT_PRESENT, 1,
				[__free() cleanup attribute is not supported])
		])
	])
])
