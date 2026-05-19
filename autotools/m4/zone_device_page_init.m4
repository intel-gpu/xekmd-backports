dnl #
dnl # v7.0 - zone_device_page_init() gained pgmap and order arguments
dnl #
AC_DEFUN([AC_ZONE_DEVICE_PAGE_INIT_3ARGS_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/memremap.h>
		],[
			struct page *p = NULL;
			struct dev_pagemap *pgmap = NULL;
			zone_device_page_init(p, pgmap, 0);
		],[
		],[
			AC_DEFINE(BPM_ZONE_DEVICE_PAGE_INIT_3ARGS_NOT_PRESENT, 1,
				[zone_device_page_init still takes 1 arg])
		])
	])
])
