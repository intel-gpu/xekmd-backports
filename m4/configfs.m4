dnl #
dnl # v6.12 - 0e6a35b93745bb
dnl # fs/configfs: Add a callback to determine attribute visibility
dnl #
AC_DEFUN([AC_CONFIGFS_GROUP_OPS_IS_VISIBLE_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/configfs.h>
		],[
			struct configfs_group_operations ops = {
				.is_visible = NULL,
			};
		],[
		],[
			AC_DEFINE([BPM_CONFIGFS_GROUP_OPS_IS_VISIBLE_NOT_PRESENT], 1,
				[configfs_group_operations.is_visible not available])
		])
	])
])
