dnl #
dnl # v6.11-0edb555a65d1
dnl # platform: Make platform_driver::remove() return void
dnl #
AC_DEFUN([AC_PF_DRIVER_REMOVE_RETURN_VOID_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/platform_device.h>
		],[
			void remove_cb(struct platform_device *pdev);
			struct platform_driver pdrv = { .remove = remove_cb };
			(void)pdrv;
		],[
		],[
			AC_DEFINE([BPM_PF_DRIVER_REMOVE_RETURN_VOID_NOT_PRESENT], 1,
				[platform_device.remove callback returns int])
		])
	])
])
