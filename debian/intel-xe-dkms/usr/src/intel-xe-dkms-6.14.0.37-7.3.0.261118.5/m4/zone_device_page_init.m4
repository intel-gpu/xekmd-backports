dnl #
dnl # v7.0-12b2285bf3d1
dnl # mm/zone_device: reinitialize large zone device private folios
dnl #
AC_DEFUN([AC_ZONE_DEVICE_PAGE_INIT_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/memremap.h>
		],[
			zone_device_page_init(NULL, NULL, 0);
		],[
		],[
			AC_DEFINE(BPM_ZONE_DEVICE_PAGE_INIT_3ARGS_NOT_PRESENT, 1,
				[zone_device_page_init does not take 3 args])

			AC_KERNEL_TRY_COMPILE([
				#include <linux/memremap.h>
			],[
				zone_device_page_init(NULL, NULL);
			],[
			],[
				AC_DEFINE(BPM_ZONE_DEVICE_PAGE_INIT_2ARGS_NOT_PRESENT, 1,
					[zone_device_page_init does not take 2 args])

				AC_KERNEL_TRY_COMPILE([
					#include <linux/memremap.h>
				],[
					zone_device_page_init(NULL);
				],[
				],[
					AC_DEFINE(BPM_ZONE_DEVICE_PAGE_INIT_1ARG_NOT_PRESENT, 1,
						[zone_device_page_init does not take 1 arg])
				])
			])
		])
	])
])
