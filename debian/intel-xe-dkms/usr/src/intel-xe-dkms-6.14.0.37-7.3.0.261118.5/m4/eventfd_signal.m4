dnl #
dnl # v6.8-3652117f8548
dnl # eventfd: simplify eventfd_signal()
dnl #
AC_DEFUN([AC_EVENTFD_SIGNAL_ARG1_NOT_PRESENT], [
	AC_KERNEL_DO_BACKGROUND([
		AC_KERNEL_TRY_COMPILE([
			#include <linux/eventfd.h>
		],[
			struct eventfd_ctx *ctx = NULL;

			eventfd_signal(ctx);
		],[
		],[
			AC_DEFINE(BPM_EVENTFD_SIGNAL_ARG1_NOT_PRESENT, 1,
				[eventfd_signal() requires an extra count argument])
		])
	])
])
