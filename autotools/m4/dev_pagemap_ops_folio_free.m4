dnl #
dnl # da0c02516c50 
dnl # mm/list_lru: simplify the list_lru walk callback function
dnl #

AC_DEFUN([AC_DEV_PAGEMAP_OPS_FOLIO_FREE_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/memremap.h>
		],[
			struct dev_pagemap_ops ops = { .folio_free = NULL };
			(void)ops;
		],[
		],[
			AC_DEFINE(BPM_DEV_PAGEMAP_OPS_FOLIO_FREE_NOT_PRESENT, 1,
				[struct dev_pagemap_ops has no folio_free member])
		])
	])
])

dnl #
dnl # v6.7+ - folio_zone_device_data() added to linux/memremap.h
dnl #
AC_DEFUN([AC_FOLIO_ZONE_DEVICE_DATA_NOT_PRESENT], [
       AC_KERNEL_DO_BACKGROUND([
               AC_KERNEL_TRY_COMPILE([
                       #include <linux/memremap.h>
               ],[
                       struct folio *folio = NULL;
                       (void)folio_zone_device_data(folio);
               ],[
               ],[
                       AC_DEFINE(BPM_FOLIO_ZONE_DEVICE_DATA_NOT_PRESENT, 1,
                               [folio_zone_device_data() is not available])
               ])
       ])
])
