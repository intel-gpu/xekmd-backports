dnl #
dnl # v7.0 - struct dev_pagemap_ops gained folio_free callback
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
dnl # 2e03c0c5c59a
dnl # drm/pagemap: Add helper to access zone_device_data
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
