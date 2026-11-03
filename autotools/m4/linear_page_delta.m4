dnl #
dnl #  v7.3 - 7e6543d1f939
dnl #  mm: introduce linear_anon_page_index()
dnl #

AC_DEFUN([AC_LINEAR_PAGE_DELTA_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/pagemap.h>
		], [
			struct vm_area_struct *vma = NULL;

			(void)linear_page_delta(vma, 0);
		], [
		], [
			AC_DEFINE(BPM_LINEAR_PAGE_DELTA_NOT_PRESENT, 1,
				  [linear_page_delta() is not available])
		])
	])
])
