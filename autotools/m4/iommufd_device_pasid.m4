dnl #
dnl # v6.15-2fb69c602d57
dnl # iommufd: Support pasid attach/replace
dnl #
AC_DEFUN([AC_IOMMUFD_DEVICE_PASID_ATTACH_REPLACE_DETACH_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/iommufd.h>
		],[
			struct iommufd_device *idev = NULL;
			u32 pt_id = 0;

			iommufd_device_attach(idev, 0, &pt_id);
		],[
		],[
			AC_DEFINE(BPM_IOMMUFD_DEVICE_PASID_ATTACH_REPLACE_DETACH_NOT_PRESENT, 1,
				[iommufd PASID attach/replace/detach APIs are not available])
		])
	])
])
