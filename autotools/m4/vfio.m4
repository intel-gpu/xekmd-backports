dnl #
dnl # v7.0-rc1 - 775f726a742a
dnl # vfio: Add get_region_info_caps op
dnl #
dnl #
AC_DEFUN([AC_VFIO_GET_REGION_INFO_CAPS_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/vfio.h>
		],[
			static const struct vfio_device_ops ops = {
				.get_region_info_caps = NULL,
			};
			(void)ops;
		],[
		],[
			AC_DEFINE(BPM_VFIO_GET_REGION_INFO_CAPS_NOT_PRESENT, 1,
				[struct vfio_device_ops does not have get_region_info_caps member])
		])
	])
])
