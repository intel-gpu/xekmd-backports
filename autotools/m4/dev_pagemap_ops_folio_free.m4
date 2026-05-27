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
