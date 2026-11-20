dnl #
dnl # v6.4-1aaba11da9aa
dnl # driver core: class: remove module * from class_create()
dnl #
AC_DEFUN([AC_CLASS_CREATE_NO_OWNER_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/device.h>
		],[
			class_create("test_class");
		],[
		],[
			AC_DEFINE(BPM_CLASS_CREATE_NO_OWNER_NOT_PRESENT, 1,
				[class_create() still requires owner parameter])
		])
	])
])

dnl #
dnl # v6.5-6265539776a0
dnl # driver core: Add device_set_driver_override() helper
dnl #
AC_DEFUN([AC_DEVICE_SET_DRIVER_OVERRIDE_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/device.h>
		],[
			device_set_driver_override(NULL, NULL);
		],[
		],[
			AC_DEFINE(BPM_DEVICE_SET_DRIVER_OVERRIDE_NOT_PRESENT, 1,
				[device_set_driver_override() is not available])
		])
	])
])

dnl #
dnl # v6.18-cb3d1049f4ea
dnl # driver core: generalize driver_override in struct device
dnl #
AC_DEFUN([AC_STRUCT_DEVICE_DRIVER_OVERRIDE_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/device.h>
		],[
			struct device *dev = NULL;

			(void)dev->driver_override;
		],[
		],[
			AC_DEFINE(BPM_STRUCT_DEVICE_DRIVER_OVERRIDE_NOT_PRESENT, 1,
				[struct device has no driver_override member])
		])
	])
])
