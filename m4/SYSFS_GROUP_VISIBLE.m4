dnl #
dnl # v6.17-d9a078809356
dnl # platform/x86/intel/pmt: Add PMT Discovery driver
dnl #
AC_DEFUN([AC_DEFINE_SYSFS_GROUP_VISIBLE_NOT_PRESENT], [
        AC_KERNEL_DO_BACKGROUND([
                AC_KERNEL_TRY_COMPILE([
                        #include <linux/sysfs.h>
		],[
			DEFINE_SYSFS_GROUP_VISIBLE;
		],[
		],[
			AC_DEFINE(BPM_DEFINE_SYSFS_GROUP_VISIBLE_NOT_PRESENT, 1,
				[DEFINE_SYSFS_GROUP_VISIBLE is not avilable])
		])
	])
])
