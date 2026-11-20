dnl #
dnl # v6.11-d69d80484598
dnl # driver core: have match() callback in struct bus_type take a const *
dnl #
AC_DEFUN([AC_MEI_CL_DEVICE_MATCH_CONST_ARG_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/device.h>
			#include <linux/device/bus.h>
		],[
			int mei_cl_device_match(struct device *dev,
						 const struct device_driver *drv);
			struct bus_type test_bus = {
				.match = mei_cl_device_match,
			};
			(void)test_bus;
		],[
		],[
			AC_DEFINE([BPM_MEI_CL_DEVICE_MATCH_CONST_ARG_NOT_PRESENT], 1,
				[const argument not supported in struct bus_type match callback])
		])
	])
])
