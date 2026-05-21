dnl #
dnl # v7.0 - vma_alloc_folio() dropped the hugepage parameter
dnl #
AC_DEFUN([AC_VMA_ALLOC_FOLIO_4ARGS_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/gfp.h>
			#include <linux/mm.h>
		],[
			struct folio *f;
			struct vm_area_struct *vma = NULL;
			f = vma_alloc_folio(GFP_KERNEL, 0, vma, 0);
			(void)f;
		],[
		],[
			AC_DEFINE(BPM_VMA_ALLOC_FOLIO_4ARGS_NOT_PRESENT, 1,
				[vma_alloc_folio still takes 5 args including hugepage])
		])
	])
])
