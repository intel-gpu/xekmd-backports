dnl #
dnl # v7.0 - page_pgmap() helper in mmzone.h
dnl #
AC_DEFUN([AC_PAGE_PGMAP_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mmzone.h>
			#include <linux/mm.h>
		],[
			struct page *p = NULL;
			struct dev_pagemap *pgmap = page_pgmap(p);
			(void)pgmap;
		],[
		],[
			AC_DEFINE(BPM_PAGE_PGMAP_NOT_PRESENT, 1,
				[page_pgmap() helper is not available])
		])
	])
])
