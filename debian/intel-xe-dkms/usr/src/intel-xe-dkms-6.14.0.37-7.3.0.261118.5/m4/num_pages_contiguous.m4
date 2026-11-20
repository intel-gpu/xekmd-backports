dnl #
dnl # v6.18 - 929bf010e059 ("mm: introduce num_pages_contiguous()")
dnl #
AC_DEFUN([AC_NUM_PAGES_CONTIGUOUS_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mm.h>
			#include <linux/mm_inline.h>
		],[
			(void)num_pages_contiguous;
		],[
		],[
			AC_DEFINE(BPM_NUM_PAGES_CONTIGUOUS_NOT_PRESENT, 1,
				[num_pages_contiguous is not available])
		])
	])
])
