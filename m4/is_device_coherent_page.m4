dnl #
dnl # v6.0 -f25cbb7a95a2
dnl # mm: add zone device coherent type memory support
dnl #
AC_DEFUN([AC_IS_DEVICE_COHERENT_PAGE_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/memremap.h>
		],[
			is_device_coherent_page(NULL);
		],[
		],[
			AC_DEFINE(BPM_IS_DEVICE_COHERENT_PAGE_NOT_PRESENT, 1,
				[is_device_coherent_page() is not present])
		])
	])
])
