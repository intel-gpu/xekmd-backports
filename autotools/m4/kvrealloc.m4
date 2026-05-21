dnl #
dnl # v5.16-8587ca6f3415
dnl # mm: move kvmalloc-related functions to slab.h
dnl # v5.16-56bcf40f91c7d mm/kvmalloc: add __alloc_size attributes
dnl # dropped oldsize parameter from kvrealloc signature
dnl #
AC_DEFUN([AC_KVREALLOC_OLDSIZE_PARAM_REMOVED], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mm.h>
		],[
			void *p = NULL;
			kvrealloc(p, PAGE_SIZE, GFP_KERNEL);
		],[
		],[
			AC_DEFINE(BPM_KVREALLOC_OLDSIZE_PARAM_PRESENT, 1,
				[kvrealloc() requires oldsize parameter])
		])
	])
])
