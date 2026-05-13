dnl #
dnl # v5.16-b620f63358cd
dnl # mm: Add folio_put()
dnl #
AC_DEFUN([AC_FOLIO_PUT_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mm.h>
			#include <linux/pagemap.h>
		], [
			folio_put(NULL);
		], [
		], [
			AC_DEFINE(BPM_FOLIO_PUT_NOT_PRESENT, 1,
				  [folio_put() is not available in the kernel])
		])
	])
])
