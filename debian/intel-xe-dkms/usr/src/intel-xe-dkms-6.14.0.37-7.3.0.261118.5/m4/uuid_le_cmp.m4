dnl #
dnl # v6.10-1fb1ea0d9cb8 mei: Move uuid.h to the MEI namespace
dnl #
AC_DEFUN([AC_UUID_LE_CMP_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/mei_uuid.h>
		], [
			uuid_le_cmp(NULL_UUID_LE, NULL_UUID_LE);
		], [
		], [
			AC_DEFINE([BPM_UUID_LE_CMP_NOT_PRESENT], 1,
				[uuid_le_cmp() is not available])
		])
	])
])
