dnl #
dnl # v6.2-20b0b53aca43
dnl # genetlink: introduce split op representation
dnl #
AC_DEFUN([AC_GENL_SPLIT_OPS_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <net/genetlink.h>
		], [
			struct genl_split_ops op = {};
			struct genl_family family = {};

			family.split_ops = &op;
			family.n_split_ops = 1;
		], [
		], [
			AC_DEFINE(BPM_GENL_SPLIT_OPS_NOT_PRESENT, 1,
				[genl_split_ops API is not available])
		])
	])
])
