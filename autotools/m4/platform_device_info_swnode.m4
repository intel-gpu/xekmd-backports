dnl #
dnl # v7.3 - 0fc434bc2c45
dnl # driver core: platform: allow attaching software nodes when creating devices
dnl #
AC_DEFUN([AC_PLATFORM_DEVICE_INFO_SWNODE_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/platform_device.h>
		],[
			struct platform_device_info info = {
				.swnode = NULL,
			};
			(void)info;
		],[
		],[
			AC_DEFINE([BPM_PLATFORM_DEVICE_INFO_SWNODE_NOT_PRESENT], 1,
				[platform_device_info.swnode not available])
		])
	])
])
