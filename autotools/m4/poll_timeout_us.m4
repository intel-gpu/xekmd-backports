dnl poll_timeout_us.m4 - check for poll_timeout_us macro
AC_DEFUN([AC_POLL_TIMEOUT_US_NOT_PRESENT], [
AC_KERNEL_DO_BACKGROUND([
AC_KERNEL_TRY_COMPILE([
#include <linux/iopoll.h>
], [
int x;
(void)poll_timeout_us(x = 1, x, 10, 1000, false);
], [
AC_MSG_RESULT(yes)
], [
AC_DEFINE(BPM_POLL_TIMEOUT_US_NOT_PRESENT, 1,
[poll_timeout_us is not available])
AC_MSG_RESULT(no)
])
])
])
