dnl #
dnl # v6.18 - bd0dbbb3fd90
dnl # mm: reimplement folio_is_device_coherent()
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
